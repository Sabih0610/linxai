"""Generic NETCONF config-feature engine (device.config.read / set / restore).

Embedded in the NETCONF worker after the feature catalog (netconf_features.py).
Snapshot the feature's target node, merge the desired config through commit_edit
(lock-or-refuse, validate, confirmed commit, read-back, confirm), verify every desired
leaf, and restore by replacing the target with its snapshot or removing it if it was
absent. Namespace prefixes from the device's reply are kept so identityref values in a
restored snapshot stay valid.
"""

CONFIG_CODE = r'''
import socket as _socket
def _locate(root, path):
    node = root
    for ns_key, tag, keys, *_ in path:
        match = None
        for child in node.findall('{%s}%s' % (NS[ns_key], tag)):
            if all((child.findtext('{%s}%s' % (NS[ns_key], k)) or '').strip().split(':')[-1] == str(v) for k, v in keys.items()):
                match = child; break
        if match is None: return None
        node = match
    return node
def read_target(m, path):
    raw = m.get_config(source='running', filter=('subtree', render(path))).data_xml
    node = _locate(ET.fromstring(raw), path)
    text = ET.tostring(node, encoding='unicode') if node is not None else ''
    prefixes = dict(_re.findall(r'xmlns:([A-Za-z_][\w.-]*)="([^"]+)"', raw))
    digest = hashlib.sha256(ET.canonicalize(text).encode() if text else b'').hexdigest()
    return node, text, digest, prefixes
def existing_depth(m, path):
    """How many leading path entries already exist. Each ancestor is probed with its OWN filter:
    devices answer a filter on a missing entry with empty data, hiding ancestors that do exist."""
    for i in range(len(path), 0, -1):
        raw = m.get_config(source='running', filter=('subtree', render(path[:i]))).data_xml
        if _locate(ET.fromstring(raw), path[:i]) is not None: return i
    return 0
def _values(node, rel):
    found = [node]
    for name in rel:
        found = [c for n in found for c in n if c.tag.split('}')[-1] == name]
    return [(c.text or '').strip().split(':')[-1] for c in found]
def matches(node, config):
    return node is not None and all(str(v).split(':')[-1] in _values(node, rel) for rel, v in expected_leaves(config))
def _leaves(text):
    out = []
    def walk(n, rel):
        kids = list(n)
        if not kids: out.append((rel, (n.text or '').strip().split(':')[-1])); return
        for c in kids: walk(c, rel + (c.tag.split('}')[-1],))
    if text: walk(ET.fromstring(text), ())
    return out
def _wrap(xml): return '<nc:config xmlns:nc="%s">%s</nc:config>' % (NC, xml)
def _asset_resolved():
    try: return dict(asset, host=_socket.gethostbyname(asset['host']))
    except OSError: return asset
def config_main(m):
    feature, settings = params['feature'], json.loads(params['settings_json'])
    if action == 'device.config.restore':
        transaction = state_dir / 'transactions' / (params['transaction_id'] + '.json')
        saved = json.loads(read(transaction)); feature, settings = saved['feature'], saved['settings']
    path, config = resolve(feature, settings, _asset_resolved())     # guards re-run with the resolved address
    node, text, current, prefixes = read_target(m, path)
    if action == 'device.config.read':
        print(json.dumps({'verified': True, 'platform': 'netconf', 'feature': feature, 'present': node is not None,
                          'current': text[:8192], 'revision': current})); return
    token = params['transaction_id']; uuid.UUID(token)
    transactions = state_dir / 'transactions'
    if transactions.exists(): chain(transactions, True)
    transaction = transactions / (token + '.json')
    if action == 'device.config.set':
        if mode in ('check', 'apply') and current != params['expected_revision']: raise ValueError('Device state changed; read and preview again')
        if mode == 'check':
            if transaction.exists(): raise ValueError('Consumed device transaction ID')
            print(json.dumps({'revision': current, 'feature': feature, 'present': node is not None})); return
        if mode == 'apply':
            if len(text) > 60000: raise ValueError('Target too large to snapshot safely')
            if not transactions.exists(): transactions.mkdir(mode=0o700)
            if sum(1 for _ in transactions.iterdir()) >= 1000: raise ValueError('Transaction retention full; archive before mutation')
            atomic(transaction, encoded({'schema': 1, 'asset': params['asset'], 'uid': uid, 'feature': feature, 'settings': settings,
                                         'prior': text, 'prefixes': prefixes, 'existing_depth': existing_depth(m, path),
                                         'created': time.time(), 'state': 'captured',
                                         'operation_id': request['operation_id']}), True)
            commit_edit(m, _wrap(render(path, config)), lambda: matches(read_target(m, path)[0], config))
            node, text, current, _ = read_target(m, path)
        saved = json.loads(read(transaction))
        if not matches(node, config): raise ValueError('Device postcondition failed')
        restoration = {'action': 'device.config.restore', 'parameters': {'asset': params['asset'], 'feature': feature,
                       'settings': settings, 'transaction_id': token, 'expected_revision': current}}
        print(json.dumps({'verified': True, 'platform': 'netconf', 'feature': feature, 'revision': current, 'restoration': restoration,
                          'diff': {'feature': feature, 'settings': settings, 'previously_present': bool(saved['prior'])}}))
        return
    # device.config.restore
    if saved['asset'] != params['asset'] or saved['uid'] != uid or time.time() - saved['created'] > 300: raise ValueError('Restoration scope/expiry mismatch')
    if mode in ('check', 'apply') and (saved['state'] != 'captured' or current != params['expected_revision']):
        raise ValueError('Restoration stale, consumed or altered')
    if mode == 'check': print(json.dumps({'revision': current, 'feature': feature, 'restore_present': bool(saved['prior'])})); return
    prior, want = saved['prior'], _leaves(saved['prior'])
    if prior:
        decls = ''.join(' xmlns:%s="%s"' % (p, u) for p, u in saved['prefixes'].items() if _re.fullmatch(r'[A-Za-z_][\w.-]*', p) and p != 'nc')
        inner = ''.join(ET.tostring(c, encoding='unicode') for c in ET.fromstring(prior))
        xml = _wrap(render(path, operation='replace', inner_xml=inner, extra=decls))
    else:
        # Remove the highest LIST ENTRY this change created (e.g. a new protocol instance or
        # subinterface), never a bare container, which devices may refuse to remove.
        depth = saved.get('existing_depth', len(path) - 1)
        top = next((i for i in range(depth, len(path)) if path[i][2]), len(path) - 1)
        xml = _wrap(render(path[:top + 1], operation='remove'))
    def restored():
        n, t, _, _ = read_target(m, path)
        return n is None if not prior else set(want) <= set(_leaves(t))
    if mode == 'apply':
        commit_edit(m, xml, restored); saved['state'] = 'restored'; atomic(transaction, encoded(saved))
    if not restored(): raise ValueError('Restoration postcondition failed')
    print(json.dumps({'verified': True, 'platform': 'netconf', 'restored': True, 'feature': feature}))
def _provisional(m, xml):
    """Stage, validate and confirmed-commit WITHOUT confirming (lock-or-refuse, private-candidate fallback)."""
    try: m.lock('candidate'); locked = True
    except RPCError as exc: raise ValueError('Device candidate is locked or holds uncommitted changes') from exc
    try:
        _discard(m); m.edit_config(target='candidate', config=xml); m.validate(source='candidate')
        _busy(lambda: m.commit(confirmed=True, timeout=str(CONFIRM_TIMEOUT_S))); return
    except RPCError as exc:
        _discard(m)
        if 'same configuration session' not in str(exc): raise
    finally:
        try: m.unlock('candidate')
        except Exception: pass
    _discard(m); m.edit_config(target='candidate', config=xml); m.validate(source='candidate')
    _busy(lambda: m.commit(confirmed=True, timeout=str(CONFIRM_TIMEOUT_S)))
def batch_main():
    """Coordinated change across up to 4 devices: all confirmed-committed, all verified, then all
    confirmed; any failure cancels every provisional commit (timer and session drop are backstops)."""
    global asset, state_dir
    changes, devices, token = json.loads(params['changes_json']), request['assets'], params['transaction_id']
    sessions = []
    try:
        for ch in changes:
            asset = devices[ch['asset']]; state_dir = pathlib.Path(asset['state_dir']); chain(state_dir, True)
            m = connect(write=True)
            path, config = resolve(ch['feature'], ch['settings'], _asset_resolved())
            node, text, current, prefixes = read_target(m, path)
            sessions.append({'m': m, 'ch': ch, 'path': path, 'config': config, 'prior': text, 'prefixes': prefixes,
                             'depth': existing_depth(m, path), 'state_dir': state_dir, 'asset': asset})
            if mode in ('check', 'apply') and current != ch['expected_revision']:
                raise ValueError('%s: device state changed; read and preview again' % ch['asset'])
        if mode == 'check':
            print(json.dumps({'devices': [s['ch']['asset'] for s in sessions]})); return
        if mode == 'apply':
            for s in sessions:               # one single-device transaction per device enables typed restores
                sub = str(uuid.uuid5(uuid.UUID(token), s['ch']['asset'])); s['token'] = sub
                txdir = s['state_dir'] / 'transactions'
                if not txdir.exists(): txdir.mkdir(mode=0o700)
                atomic(txdir / (sub + '.json'), encoded({'schema': 1, 'asset': s['ch']['asset'], 'uid': uid, 'feature': s['ch']['feature'],
                       'settings': s['ch']['settings'], 'prior': s['prior'], 'prefixes': s['prefixes'], 'existing_depth': s['depth'],
                       'created': time.time(), 'state': 'captured', 'operation_id': request['operation_id'], 'batch': token}), True)
            committed = []
            try:
                for s in sessions:
                    _provisional(s['m'], _wrap(render(s['path'], s['config']))); committed.append(s)
                if not all(matches(read_target(s['m'], s['path'])[0], s['config']) for s in sessions):
                    raise ValueError('Read-back failed on at least one device')
                for s in sessions: _busy(s['m'].commit)
            except Exception:
                for s in committed:
                    try: s['m'].cancel_commit()
                    except Exception: pass
                raise
        else:
            for s in sessions: s['token'] = str(uuid.uuid5(uuid.UUID(token), s['ch']['asset']))
        if not all(matches(read_target(s['m'], s['path'])[0], s['config']) for s in sessions):
            raise ValueError('Batch postcondition failed')
        restorations = [{'action': 'device.config.restore', 'parameters': {'asset': s['ch']['asset'], 'feature': s['ch']['feature'],
                         'settings': s['ch']['settings'], 'transaction_id': s['token'], 'expected_revision': read_target(s['m'], s['path'])[2]}}
                        for s in sessions]
        print(json.dumps({'verified': True, 'platform': 'netconf', 'batch': True, 'devices': [s['ch']['asset'] for s in sessions],
                          'restorations': restorations}))
    finally:
        for s in sessions:
            try: s['m'].close_session()
            except Exception: pass
if action == 'device.config.batch':
    batch_main(); raise SystemExit(0)
'''
