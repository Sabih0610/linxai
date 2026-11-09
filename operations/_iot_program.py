"""IoT branch of the fixed workflow worker (MQTT and Modbus/TCP).

Runs as the ordinary owner inside WORKFLOW_PROGRAM for `iot.*` actions. Only the
asset's configured points are touched; values were bounds-checked at preparation
and are checked again here.
  Modbus: read the configured registers/coils; a write is read back from the device.
  MQTT:   read the retained state topics; a write publishes to the configured command
          topic and is verified only when the device itself reports the new value on
          its state topic (the broker accepting a publish proves nothing).
Every write captures the prior value in a single-use transaction for a 300 s restore.
"""

IOT_CODE = r'''
asset = request['asset']
state_dir = pathlib.Path(asset['state_dir']); chain(state_dir, True)
points = asset['points']
# The revision covers writable points only: sensor readings may drift between preview and apply.
WRITABLE = sorted(n for n, spec in points.items() if (spec.get('writable') if asset['platform'] == 'modbus' else spec.get('command_topic')))
def state_revision(value): return revision({n: value[n] for n in WRITABLE})
def bounded(point, value):
    spec = points[point]
    if asset['platform'] == 'modbus' and spec['kind'] == 'coil':
        ok = type(value) is bool
    elif 'values' in spec:
        ok = value in spec['values']
    else:
        ok = type(value) is int and spec['min'] <= value <= spec['max']
    if not ok: raise ValueError('Value outside the configured bounds')
    return value
if asset['platform'] == 'modbus':
    from pymodbus.client import ModbusTcpClient
    client = ModbusTcpClient(asset['host'], port=asset['port'], timeout=5)
    if not client.connect(): raise ConnectionError('Modbus device unreachable')
    def _check(reply):
        if reply.isError(): raise ValueError('Modbus exception: ' + str(reply)[:200])
        return reply
    def read_all():
        out = {}
        for name, spec in sorted(points.items()):
            a, u = spec['address'], asset['unit']
            if spec['kind'] == 'holding': out[name] = _check(client.read_holding_registers(a, 1, slave=u)).registers[0]
            elif spec['kind'] == 'input': out[name] = _check(client.read_input_registers(a, 1, slave=u)).registers[0]
            elif spec['kind'] == 'coil': out[name] = bool(_check(client.read_coils(a, 1, slave=u)).bits[0])
            else: out[name] = bool(_check(client.read_discrete_inputs(a, 1, slave=u)).bits[0])
        return out
    def write(point, value):
        spec = points[point]
        if spec['kind'] == 'holding': _check(client.write_register(spec['address'], bounded(point, value), slave=asset['unit']))
        elif spec['kind'] == 'coil': _check(client.write_coil(spec['address'], bounded(point, value), slave=asset['unit']))
        else: raise ValueError('Read-only point')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if read_all()[point] == value: return
            time.sleep(0.2)
        raise ValueError('Device did not report the written value')
    close = client.close
else:
    import paho.mqtt.client as mqtt, threading
    password = read(pathlib.Path(asset['password_file'])).decode().strip()
    seen, cond = {}, threading.Condition()
    by_topic = {spec['state_topic']: name for name, spec in points.items()}
    client = mqtt.Client(client_id='linxai-' + uuid.uuid4().hex[:12], clean_session=True)
    client.username_pw_set(asset['username'], password)
    if asset['ca_file']: client.tls_set(ca_certs=asset['ca_file'])
    def on_message(_c, _u, msg):
        if msg.topic in by_topic:
            with cond:
                seen[by_topic[msg.topic]] = msg.payload.decode(errors='replace')[:64]; cond.notify_all()
    client.on_message = on_message
    connack = {}
    def on_connect(_c, _u, _flags, rc):
        with cond:
            connack['rc'] = rc; cond.notify_all()
    client.on_connect = on_connect
    if client.connect(asset['host'], asset['port'], keepalive=30) != 0: raise ConnectionError('MQTT broker refused the connection')
    client.loop_start()
    # connect() only opens the socket; authentication succeeds only on an explicit CONNACK 0.
    with cond:
        deadline = time.monotonic() + 5
        while 'rc' not in connack and time.monotonic() < deadline: cond.wait(0.1)
    if connack.get('rc') != 0:
        client.loop_stop(); client.disconnect()
        raise PermissionError('MQTT broker did not accept the session (CONNACK %s)' % connack.get('rc', 'timeout'))
    client.subscribe([(topic, 1) for topic in by_topic])
    def decode(point, raw):
        spec = points[point]
        if raw is None: return None
        return int(raw) if 'min' in spec and raw.lstrip('-').isdigit() else raw
    def read_all(wait=2.0):
        deadline = time.monotonic() + wait
        with cond:
            while len(seen) < len(points) and time.monotonic() < deadline: cond.wait(0.2)
            return {name: decode(name, seen.get(name)) for name in sorted(points)}
    def write(point, value):
        bounded(point, value)
        with cond: seen.pop(point, None)
        info = client.publish(points[point]['command_topic'], str(value), qos=1, retain=False)
        info.wait_for_publish(5)
        deadline = time.monotonic() + 10
        with cond:
            while time.monotonic() < deadline:
                if decode(point, seen.get(point)) == value: return
                cond.wait(0.2)
        raise ValueError('Device did not report the commanded value on its state topic')
    def close():
        client.loop_stop(); client.disconnect()
try:
    value = read_all(); current = state_revision(value)
    if action == 'iot.inspect':
        if mode == 'check':
            # Prerequisite evidence must be stable between the two checks; sensor readings drift.
            print(json.dumps({'reachable': True, 'revision': current})); raise SystemExit(0)
        print(json.dumps({'verified': True, 'platform': asset['platform'], 'points': value, 'revision': current})); raise SystemExit(0)
    token = params['transaction_id']; uuid.UUID(token)
    transactions = state_dir / 'transactions'
    if transactions.exists(): chain(transactions, True)
    transaction = transactions / (token + '.json')
    if action == 'iot.point.set':
        point, wanted = params['point'], params['value']
        if mode in ('check', 'apply') and current != params['expected_revision']: raise ValueError('Device state changed; inspect and preview again')
        if mode == 'check':
            if transaction.exists(): raise ValueError('Consumed IoT transaction ID')
            print(json.dumps({'revision': current, 'before': value[point], 'after': wanted})); raise SystemExit(0)
        if mode == 'apply':
            if not transactions.exists(): transactions.mkdir(mode=0o700)
            if sum(1 for _ in transactions.iterdir()) >= 1000: raise ValueError('Transaction retention full; archive before mutation')
            atomic(transaction, encoded({'schema': 1, 'asset': params['asset'], 'uid': uid, 'point': point, 'prior': value[point],
                                         'value': wanted, 'created': time.time(), 'state': 'captured',
                                         'operation_id': request['operation_id']}), True)
            write(point, wanted); value = read_all()
        saved = json.loads(read(transaction))
        if value[point] != wanted: raise ValueError('Device postcondition failed')
        current = state_revision(value)
        restoration = {'action': 'iot.point.restore', 'parameters': {'asset': params['asset'], 'transaction_id': token, 'expected_revision': current}}
        print(json.dumps({'verified': True, 'platform': asset['platform'], 'revision': current, 'restoration': restoration,
                          'diff': {'point': point, 'from': saved['prior'], 'to': wanted}}))
    elif action == 'iot.point.restore':
        saved = json.loads(read(transaction))
        if saved['asset'] != params['asset'] or saved['uid'] != uid or time.time() - saved['created'] > 300: raise ValueError('Restoration scope/expiry mismatch')
        if mode in ('check', 'apply') and (saved['state'] != 'captured' or current != params['expected_revision'] or value[saved['point']] != saved['value']):
            raise ValueError('Restoration stale, consumed or altered')
        if saved['prior'] is None: raise ValueError('Prior value unknown; manual review required')
        if mode == 'check': print(json.dumps({'revision': current, 'point': saved['point'], 'restore_to': saved['prior']})); raise SystemExit(0)
        if mode == 'apply':
            write(saved['point'], saved['prior']); saved['state'] = 'restored'; atomic(transaction, encoded(saved))
        if read_all()[saved['point']] != saved['prior']: raise ValueError('Restoration postcondition failed')
        print(json.dumps({'verified': True, 'platform': asset['platform'], 'restored': True, 'point': saved['point'], 'value': saved['prior']}))
    else: raise ValueError('Unsupported IoT action')
finally:
    try: close()
    except Exception: pass
'''
