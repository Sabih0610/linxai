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
    # The management-address guard needs the device's real address: fail closed when the
    # name cannot be resolved instead of silently skipping the guard (QA 13 Nov 2026).
    try: return dict(asset, host=_socket.gethostbyname(asset['host']))
    except OSError: pass
    try: return dict(asset, host=_socket.getaddrinfo(asset['host'], None)[0][4][0])
    except (OSError, IndexError): raise ValueError('Device address does not resolve; the management-address guard cannot be checked')
def config_main(m):
    feature, settings = params['feature'], json.loads(params['settings_json'])
    if action == 'device.config.restore':
        transaction = state_dir / 'transactions' / (params['transaction_id'] + '.json')
        saved = json.loads(read(transaction))
        # A restore reverts exactly the change the owner was shown, never another transaction's.
        if saved['feature'] != feature or json.dumps(saved['settings'], sort_keys=True) != json.dumps(settings, sort_keys=True):
            raise ValueError('Restore request does not match the recorded transaction')
        feature, settings = saved['feature'], saved['settings']
    path, config = resolve(feature, settings, _asset_resolved())     # guards re-run with the resolved address
    node, text, current, prefixes = read_target(m, path)
    if action == 'device.config.probe':
        # Validate-only: stage an example edit, let the device validate it, ALWAYS discard.
        # Running config must be unchanged (checked in every mode against the preview revision).
        if current != params['expected_revision']: raise ValueError('Device state changed; read and preview again')
        ok, error = False, ''
        if mode == 'apply':
            try: m.lock('candidate')
            except RPCError as exc: raise ValueError('Device candidate is locked or holds uncommitted changes') from exc
            try:
                _discard(m); m.edit_config(target='candidate', config=_wrap(render(path, config))); m.validate(source='candidate'); ok = True
            except RPCError as exc: error = ' '.join(str(exc).split())[:300]
            finally:
                _discard(m)
                try: m.unlock('candidate')
                except Exception: pass
        print(json.dumps({'verified': True, 'platform': 'netconf', 'feature': feature, 'validated': ok,
                          'device_error': error, 'revision': current})); return
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
    prior = saved['prior']
    xml = _wrap(_undo_xml(path, prior, saved['prefixes'], saved.get('existing_depth', len(path) - 1)))
    restored = lambda: _is_restored(m, path, prior)
    if mode == 'apply':
        commit_edit(m, xml, restored); saved['state'] = 'restored'; atomic(transaction, encoded(saved))
    if not restored(): raise ValueError('Restoration postcondition failed')
    print(json.dumps({'verified': True, 'platform': 'netconf', 'restored': True, 'feature': feature}))
def _undo_xml(path, prior, prefixes, depth):
    """Replace the target with its snapshot, or remove the highest LIST ENTRY the change created
    (e.g. a new protocol instance or subinterface), never a bare container devices may refuse."""
    if prior:
        decls = ''.join(' xmlns:%s="%s"' % (p, u) for p, u in prefixes.items() if _re.fullmatch(r'[A-Za-z_][\w.-]*', p) and p != 'nc')
        inner = ''.join(ET.tostring(c, encoding='unicode') for c in ET.fromstring(prior))
        return render(path, operation='replace', inner_xml=inner, extra=decls)
    top = next((i for i in range(depth, len(path)) if path[i][2]), len(path) - 1)
    return render(path[:top + 1], operation='remove')
def _is_restored(m, path, prior):
    n, t, _, _ = read_target(m, path)
    return n is None if not prior else set(_leaves(prior)) <= set(_leaves(t))
def _provisional(m, xml):
    """Stage, validate and confirmed-commit WITHOUT confirming (lock-or-refuse, private-candidate fallback)."""
    def stage():                       # any failure leaves the candidate clean
        _discard(m)
        try:
            m.edit_config(target='candidate', config=xml); m.validate(source='candidate')
            _busy(lambda: m.commit(confirmed=True, timeout=str(CONFIRM_TIMEOUT_S)))
        except Exception:
            _discard(m); raise
    try: m.lock('candidate')
    except RPCError as exc: raise ValueError('Device candidate is locked or holds uncommitted changes') from exc
    try: return stage()
    except RPCError as exc:
        if 'same configuration session' not in str(exc): raise
    finally:
        try: m.unlock('candidate')
        except Exception: pass
    stage()
def _compensate(m, mine):
    """Undo a device whose part of a failed batch was already confirmed (reverse order, one commit)."""
    try:
        commit_edit(m, _wrap(''.join(_undo_xml(it['path'], it['prior'], it['prefixes'], it['depth']) for it in reversed(mine))),
                    lambda: all(_is_restored(m, it['path'], it['prior']) for it in mine))
        for it in mine:
            tx = it['state_dir'] / 'transactions' / (it['token'] + '.json')
            saved = json.loads(read(tx)); saved['state'] = 'compensated'; atomic(tx, encoded(saved))
        return True
    except Exception:
        return False
def batch_main():
    """Coordinated change: ordered changes on up to 4 devices. Each device gets ONE provisional
    confirmed commit holding all its changes; all are read back, then all confirmed; any failure
    cancels every provisional commit (the timer and session drop are backstops)."""
    global asset, state_dir
    changes, devices, token = json.loads(params['changes_json']), request['assets'], params['transaction_id']
    conns, items = {}, []
    try:
        for i, ch in enumerate(changes):
            name = ch['asset']; asset = devices[name]; state_dir = pathlib.Path(asset['state_dir']); chain(state_dir, True)
            if name not in conns: conns[name] = connect(write=True)
            path, config = resolve(ch['feature'], ch['settings'], _asset_resolved())
            node, text, current, prefixes = read_target(conns[name], path)
            if mode in ('check', 'apply') and current != ch['expected_revision']:
                raise ValueError('%s: device state changed; read and preview again' % name)
            items.append({'m': conns[name], 'ch': ch, 'path': path, 'config': config, 'prior': text, 'prefixes': prefixes,
                          'state_dir': state_dir, 'token': str(uuid.uuid5(uuid.UUID(token), '%s/%d' % (name, i)))})
        if mode == 'check':
            print(json.dumps({'devices': list(conns)})); return
        if mode == 'apply':
            for it in items:                # one single-node transaction per change enables typed restores
                txdir = it['state_dir'] / 'transactions'
                if not txdir.exists(): txdir.mkdir(mode=0o700)
                atomic(txdir / (it['token'] + '.json'), encoded({'schema': 1, 'asset': it['ch']['asset'], 'uid': uid,
                       'feature': it['ch']['feature'], 'settings': it['ch']['settings'], 'prior': it['prior'],
                       'prefixes': it['prefixes'], 'existing_depth': it.setdefault('depth', existing_depth(it['m'], it['path'])),
                       'created': time.time(), 'state': 'captured', 'operation_id': request['operation_id'], 'batch': token}), True)
            committed, confirmed = [], []
            try:
                for name, m in conns.items():
                    _provisional(m, _wrap(''.join(render(it['path'], it['config']) for it in items if it['ch']['asset'] == name)))
                    committed.append(name)
                if not all(matches(read_target(it['m'], it['path'])[0], it['config']) for it in items):
                    raise ValueError('Read-back failed on at least one device')
                for name in committed: _busy(conns[name].commit); confirmed.append(name)
            except Exception as exc:
                for name in committed:
                    if name not in confirmed: _cancel(conns[name])
                undone = [name for name in confirmed if _compensate(conns[name], [it for it in items if it['ch']['asset'] == name])]
                if confirmed:
                    raise ValueError('Batch failed after %s confirmed: %s; compensated %s; NOT compensated %s'
                                     % (confirmed, exc, undone, [n for n in confirmed if n not in undone])) from exc
                raise
        if not all(matches(read_target(it['m'], it['path'])[0], it['config']) for it in items):
            raise ValueError('Batch postcondition failed')
        restorations = [{'action': 'device.config.restore', 'parameters': {'asset': it['ch']['asset'], 'feature': it['ch']['feature'],
                         'settings': it['ch']['settings'], 'transaction_id': it['token'],
                         'expected_revision': read_target(it['m'], it['path'])[2]}} for it in reversed(items)]
        print(json.dumps({'verified': True, 'platform': 'netconf', 'batch': True, 'devices': list(conns),
                          'restorations': restorations}))           # restore in this order (reverse of apply)
    finally:
        for m in conns.values():
            try: m.close_session()
            except Exception: pass
if action == 'device.config.batch':
    batch_main(); raise SystemExit(0)
'''
