"""Agentless Linux branch of the fixed workflow worker (no LINxAI on the target).

The controller runs `/usr/bin/ssh` with a pinned known_hosts file, key-only login, no
agent or forwarding, and a command built from a FIXED template for each typed action.
Only values already validated by the registry (service names, ports) are inserted, and
always shell-quoted. Output is parsed into structured JSON; changes are confirmed by a
second read (a restart must show a new ActiveEnterTimestampMonotonic).

System services are changed only through `sudo -n` (non-interactive): the target's
owner decides with a narrow sudoers rule; LINxAI never sees or types a password.
User services (`systemd_scope: user`) use `systemctl --user` and need no root.
"""

AGENTLESS_CODE = r'''
import re as _re, shlex, subprocess
asset = request['asset']
nested, nparams = params['action'], json.loads(params['parameters_json'])
user_scope = asset['systemd_scope'] == 'user'
def ssh(argv, timeout=20):
    command = shlex.join(['env', 'LC_ALL=C'] + list(argv))
    full = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no', '-o', 'ConnectTimeout=5',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile=' + asset['known_hosts'], '-i', asset['key_path'],
            '-p', str(asset['port']), '--', asset['username'] + '@' + asset['host'], command]
    result = subprocess.run(full, capture_output=True, timeout=timeout)
    if result.returncode == 255: raise ConnectionError('SSH failed (host key, reachability or login): ' + result.stderr.decode(errors='replace')[-200:])
    return result.returncode, result.stdout.decode(errors='replace')[:65536], result.stderr.decode(errors='replace')[-400:]
def systemctl(*args):
    return ['/usr/bin/systemctl'] + (['--user'] if user_scope else []) + list(args)
def unit_state(unit):
    if not _re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,250}\.service', unit): raise ValueError('Invalid unit')
    code, out, err = ssh(systemctl('show', unit, '--no-pager', '-p', 'Id,LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestampMonotonic'))
    if code != 0: raise ValueError('systemctl show failed: ' + err)
    state = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    return {k: state.get(k) for k in ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'ActiveEnterTimestampMonotonic')}
def read():
    if nested == 'disk.usage':
        code, out, err = ssh(['/usr/bin/df', '-P', '-k', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay'])
        if code != 0: raise ValueError('df failed: ' + err)
        rows = []
        for line in out.splitlines()[1:65]:
            f = line.split()
            if len(f) >= 6 and f[1].isdigit():
                rows.append({'mount': f[5], 'size_kb': int(f[1]), 'used_kb': int(f[2]), 'avail_kb': int(f[3]), 'use_pct': int(f[4].rstrip('%'))})
        return {'filesystems': rows}
    if nested == 'memory.usage':
        code, out, err = ssh(['/usr/bin/cat', '/proc/meminfo'])
        if code != 0: raise ValueError('meminfo failed: ' + err)
        info = {k: int(v.split()[0]) for k, v in (l.split(':', 1) for l in out.splitlines() if ':' in l) if v.split() and v.split()[0].isdigit()}
        total, avail = info['MemTotal'], info['MemAvailable']
        return {'total_kb': total, 'available_kb': avail, 'used_pct': round(100 * (total - avail) / total, 1)}
    if nested == 'ports.listen':
        code, out, err = ssh(['/usr/bin/ss', '-H', '-ltn'])
        if code != 0: raise ValueError('ss failed: ' + err)
        ports = []
        for line in out.splitlines()[:512]:
            f = line.split()
            if len(f) >= 4 and ':' in f[3]:
                address, port = f[3].rsplit(':', 1)
                if port.isdigit(): ports.append({'address': address.strip('[]'), 'port': int(port)})
        wanted = nparams.get('port')
        return {'listening': [p for p in ports if wanted is None or p['port'] == wanted], 'filter': wanted}
    if nested.startswith('service.'):
        return unit_state(nparams['service'])
    raise ValueError('Action not available agentlessly')
if mode == 'check':
    code, out, err = ssh(['/usr/bin/true'])
    if code != 0: raise ConnectionError('Target did not run the reachability probe')
    if nested.startswith('service.'):
        state = unit_state(nparams['service'])
        if state['LoadState'] != 'loaded': raise ValueError('Service unit is not loaded on the target')
        print(json.dumps({'reachable': True, 'unit': state['Id'], 'load': state['LoadState']}))
    else:
        print(json.dumps({'reachable': True}))
    raise SystemExit(0)
if nested in ('service.start', 'service.stop', 'service.restart'):
    unit = nparams['service']; before = unit_state(unit)
    if mode == 'apply':
        verb = nested.split('.')[1]
        argv = systemctl(verb, '--', unit) if user_scope else ['/usr/bin/sudo', '-n'] + systemctl(verb, '--', unit)
        code, out, err = ssh(argv, timeout=60)
        if code != 0:
            if 'password is required' in err or 'a terminal is required' in err:
                raise PermissionError('Target sudo policy does not allow this systemctl action non-interactively; '
                                      'the target owner must grant a narrow NOPASSWD rule')
            raise ValueError('systemctl %s failed: %s' % (verb, err))
        deadline = time.monotonic() + 15; after = unit_state(unit)
        while time.monotonic() < deadline and after['ActiveState'] in ('activating', 'deactivating', 'reloading'):
            time.sleep(0.5); after = unit_state(unit)
        if nested == 'service.restart' and after['ActiveEnterTimestampMonotonic'] == before['ActiveEnterTimestampMonotonic']:
            raise ValueError('Service did not restart (activation time unchanged)')
    else:
        after = before
    ok = (after['ActiveState'] == 'active' if nested != 'service.stop' else after['ActiveState'] in ('inactive', 'failed'))
    if not ok: raise ValueError('Service postcondition failed: ' + str(after))
    print(json.dumps({'verified': True, 'agentless': True, 'action': nested, 'before': before, 'after': after}))
else:
    print(json.dumps({'verified': True, 'agentless': True, 'action': nested, 'result': read()}))
'''
