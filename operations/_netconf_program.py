"""NETCONF device branch of the fixed workflow worker (vendor-neutral, OpenConfig).

Runs as the ordinary owner inside WORKFLOW_PROGRAM for assets whose platform is
`netconf`. No caller text ever reaches the device: the worker builds one fixed
OpenConfig edit (interface enabled true/false) for an allowlisted interface.

Safety pattern (works on Junos, IOS-XR, Huawei VRP8, Nokia SR Linux and others):
  pinned SSH host key (SHA256) checked before any RPC; key-only login
  -> required capabilities: candidate, confirmed-commit, validate, openconfig-interfaces
  -> lock candidate, discard stale edits, edit, validate
  -> confirmed commit with automatic rollback timer (CONFIRM_TIMEOUT_S)
  -> read back running config; confirm only if it matches, else cancel-commit
  -> transaction snapshot of the prior state enables a bounded restore (300 s)
"""

NETCONF_CODE = r'''
import base64, hashlib, re as _re
from xml.etree import ElementTree as ET
from ncclient import manager
OC = 'http://openconfig.net/yang/interfaces'
CONFIRM_TIMEOUT_S = 60
asset = request['asset']
state_dir = pathlib.Path(asset['state_dir']); chain(state_dir, True)
REQUIRED = ('urn:ietf:params:netconf:capability:candidate:1.0', 'urn:ietf:params:netconf:capability:confirmed-commit:1.1',
            'urn:ietf:params:netconf:capability:validate:1.')
def connect(write=True):
    auth = {'key_filename': asset['key_path']} if 'key_path' in asset else {
        'password': read(pathlib.Path(asset['password_file'])).decode().strip()}
    if 'host_key' in asset:
        # Pinned full host key enforced by the SSH handshake BEFORE authentication, so a
        # password is never offered to an impostor (required for password login).
        pin = dict(hostkey_verify=True, hostkey_b64=asset['host_key'].split()[1], unknown_host_cb=lambda *_: False)
    else:
        pin = dict(hostkey_verify=False)          # key-only login: checked right below, before any RPC
    m = manager.connect(host=asset['host'], port=asset['port'], username=asset['username'], allow_agent=False,
                        look_for_keys=False, timeout=20, **auth, **pin)
    key = m._session._transport.get_remote_server_key()
    seen = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
    if seen != asset['host_key_sha256']:
        m.close_session(); raise PermissionError('Device host key does not match the pinned fingerprint')
    caps = list(m.server_capabilities)
    missing = [c for c in REQUIRED if not any(s.startswith(c) for s in caps)]
    if not any(OC in s for s in caps):
        m.close_session(); raise ValueError('Device lacks the OpenConfig interfaces model')
    if write and missing:
        m.close_session(); raise ValueError('Device lacks required NETCONF capabilities for safe changes: ' + ', '.join(missing))
    m.linxai_writable = not missing
    return m
def interfaces(m, source='running'):
    # Configured value first; devices that keep interface config in native models (e.g.
    # IOS XR) leave the OpenConfig config tree empty, so fall back to the reported
    # OpenConfig admin-status, which every implementation fills.
    filt = ('subtree', '<interfaces xmlns="%s"><interface><name/><config/><state><admin-status/></state></interface></interfaces>' % OC)
    data = ET.fromstring(m.get(filter=filt).data_xml)
    found = {}
    for node in data.iter('{%s}interface' % OC):
        name = node.findtext('{%s}name' % OC)
        if name in asset['ports']:
            enabled = node.findtext('{%s}config/{%s}enabled' % (OC, OC))
            admin = node.findtext('{%s}state/{%s}admin-status' % (OC, OC))
            value = enabled == 'true' if enabled is not None else ({'UP': True, 'DOWN': False}.get(admin) if admin else None)
            found[name] = {'enabled': value, 'description': node.findtext('{%s}config/{%s}description' % (OC, OC))}
    return {port: found.get(port, {'enabled': None, 'description': None}) for port in asset['ports']}
def edit(m, name, enabled):
    if not _re.fullmatch(r'[A-Za-z][A-Za-z0-9_./:-]{0,31}', name): raise ValueError('Invalid interface name')
    xml = ('<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><interfaces xmlns="%s"><interface><name>%s</name><config><name>%s</name><enabled>%s</enabled>'
           '</config></interface></interfaces></nc:config>') % (OC, name, name, 'true' if enabled else 'false')
    m.edit_config(target='candidate', config=xml)
from ncclient.operations.rpc import RPCError
def _discard(m):
    try: m.discard_changes()
    except RPCError as exc:
        if 'without starting a configuration session' not in str(exc): raise
def _busy(call):
    """Devices may answer 'commit confirmed in progress' while still applying the previous commit
    (SR Linux removing a protocol); retry briefly, well inside the confirmed-commit timer."""
    for delay in (0.5, 1, 2, 4, 8, None):
        try: return call()
        except RPCError as exc:
            if delay is None or 'confirmed in progress' not in str(exc): raise
            time.sleep(delay)
def _attempt(m, xml, check):
    _discard(m)
    try:
        m.edit_config(target='candidate', config=xml)
        m.validate(source='candidate')
        _busy(lambda: m.commit(confirmed=True, timeout=str(CONFIRM_TIMEOUT_S)))
    except Exception:
        _discard(m); raise
    try:
        if not check(): raise ValueError('Read-back did not match; confirmed commit cancelled and rolled back')
        _busy(m.commit)
    except Exception:
        try: m.cancel_commit()      # roll back now instead of waiting for the timer
        except Exception: pass
        raise
def commit_edit(m, xml, check):
    """Generic safe change: lock (or refuse), edit, validate, confirmed commit, read-back, confirm."""
    # Shared-candidate devices (Junos, IOS-XR, VRP): lock first, so another operator's
    # pending edits are refused rather than discarded ("candidate has been modified").
    try:
        m.lock('candidate')
    except RPCError as exc:
        raise ValueError('Device candidate is locked or holds uncommitted changes; resolve on the device first') from exc
    try:
        return _attempt(m, xml, check)
    except RPCError as exc:
        if 'same configuration session' not in str(exc): raise
    finally:
        try: m.unlock('candidate')
        except Exception: pass
    # Private-candidate devices (e.g. Nokia SR Linux) reject a confirmed commit under a
    # candidate lock; their per-session candidate needs no lock, and the expected-revision
    # check made just before this change still refuses concurrent modifications.
    return _attempt(m, xml, check)
def change(m, name, enabled):
    edit_xml = ('<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><interfaces xmlns="%s"><interface><name>%s</name>'
                '<config><name>%s</name><enabled>%s</enabled></config></interface></interfaces></nc:config>') % (OC, name, name, 'true' if enabled else 'false')
    if not IFACE_RE.fullmatch(name): raise ValueError('Invalid interface name')
    commit_edit(m, edit_xml, lambda: interfaces(m)[name]['enabled'] is enabled)
    return interfaces(m)
IFACE_RE = _re.compile(r'[A-Za-z][A-Za-z0-9_./:-]{0,31}')
m = connect(write=action not in ('device.inspect', 'device.config.read'))
try:
    if action.startswith('device.config.'):
        config_main(m); raise SystemExit(0)
    value = interfaces(m); current = revision(value)
    if action == 'device.inspect':
        caps = [c.split('?')[0] for c in m.server_capabilities if c.startswith('urn:ietf:params:netconf:capability:')]
        print(json.dumps({'verified': True, 'platform': 'netconf', 'device': {'interfaces': value}, 'revision': current,
                          'capabilities': sorted(caps)[:32], 'writable': m.linxai_writable})); raise SystemExit(0)
    if action == 'device.initialize': raise ValueError('NETCONF devices are not initialized by LINxAI')
    token = params['transaction_id']; uuid.UUID(token)
    transactions = state_dir / 'transactions'
    if transactions.exists(): chain(transactions, True)
    transaction = transactions / (token + '.json')
    if action == 'device.interface.set':
        name = params['interface']
        if mode in ('check', 'apply') and current != params['expected_revision']: raise ValueError('Device state changed; inspect and preview again')
        if mode == 'check':
            if transaction.exists(): raise ValueError('Consumed device transaction ID')
            print(json.dumps({'revision': current, 'before': value[name]['enabled'], 'after': params['enabled']})); raise SystemExit(0)
        if mode == 'apply':
            if not transactions.exists(): transactions.mkdir(mode=0o700)
            if sum(1 for _ in transactions.iterdir()) >= 1000: raise ValueError('Transaction retention full; archive before mutation')
            desired = json.loads(json.dumps(value)); desired[name]['enabled'] = params['enabled']
            atomic(transaction, encoded({'schema': 1, 'asset': params['asset'], 'uid': uid, 'interface': name, 'prior': value,
                                         'after': revision(desired), 'created': time.time(), 'state': 'captured',
                                         'operation_id': request['operation_id']}), True)
            value = change(m, name, params['enabled']); current = revision(value)
        saved = json.loads(read(transaction))
        if value[name]['enabled'] is not params['enabled'] or current != saved['after']: raise ValueError('Device postcondition failed')
        restoration = {'action': 'device.interface.restore', 'parameters': {'asset': params['asset'], 'transaction_id': token, 'expected_revision': current}}
        print(json.dumps({'verified': True, 'platform': 'netconf', 'revision': current, 'restoration': restoration,
                          'diff': {'interface': name, 'from': saved['prior'][name]['enabled'], 'to': params['enabled']}}))
    elif action == 'device.interface.restore':
        saved = json.loads(read(transaction))
        if saved['asset'] != params['asset'] or saved['uid'] != uid or time.time() - saved['created'] > 300: raise ValueError('Restoration scope/expiry mismatch')
        if mode in ('check', 'apply') and (saved['state'] != 'captured' or current != params['expected_revision'] or current != saved['after']):
            raise ValueError('Restoration stale, consumed or altered')
        if mode == 'check': print(json.dumps({'revision': current, 'prior': revision(saved['prior']), 'transaction': token})); raise SystemExit(0)
        prior = saved['prior'][saved['interface']]['enabled']
        if mode == 'apply':
            if prior is None: raise ValueError('Prior enabled state unknown; manual review required')
            value = change(m, saved['interface'], prior); saved['state'] = 'restored'; atomic(transaction, encoded(saved))
        if interfaces(m) != saved['prior']: raise ValueError('Restoration postcondition failed')
        print(json.dumps({'verified': True, 'platform': 'netconf', 'restored': True, 'revision': revision(saved['prior'])}))
    else: raise ValueError('Unsupported workflow action')
finally:
    try: m.close_session()
    except Exception: pass
'''


def _with_config_engine(code):
    from pathlib import Path
    from ._netconf_config_program import CONFIG_CODE
    catalog = Path(__file__).with_name("netconf_features.py").read_text(encoding="utf-8")
    marker = "m = connect(write="
    if code.count(marker) != 1:
        raise RuntimeError("netconf worker layout changed")
    return code.replace(marker, "\n".join((catalog, CONFIG_CODE, marker)))


NETCONF_CODE = _with_config_engine(NETCONF_CODE)
