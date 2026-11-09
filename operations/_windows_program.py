"""Agentless Windows branch of the fixed workflow worker (no LINxAI on the target).

Same SSH hardening as the Linux branch (pinned known_hosts, key-only, BatchMode, no
agent/forwarding) against the Windows OpenSSH server. Each typed action maps to a FIXED
PowerShell template; the only inserted value is a registry-validated service name
([A-Za-z0-9_.-], no quotes or spaces possible). The script is sent as
`powershell -EncodedCommand <base64 UTF-16LE>`, so no shell quoting is involved, and it
returns compact JSON. Changes need rights on the target (an administrator or a
delegated service right); without them the target refuses and LINxAI reports it.
"""

WINDOWS_CODE = r'''
import base64, re as _re, subprocess
asset = request['asset']
nested, nparams = params['action'], json.loads(params['parameters_json'])
def ps(script, timeout=40):
    wrapped = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { " + script + " } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
    encoded = base64.b64encode(wrapped.encode('utf-16-le')).decode()
    command = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + encoded
    full = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no', '-o', 'ConnectTimeout=5',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile=' + asset['known_hosts'], '-i', asset['key_path'],
            '-p', str(asset['port']), '--', asset['username'] + '@' + asset['host'], command]
    result = subprocess.run(full, capture_output=True, timeout=timeout)
    if result.returncode == 255: raise ConnectionError('SSH failed (host key, reachability or login): ' + result.stderr.decode(errors='replace')[-200:])
    out, err = result.stdout.decode(errors='replace').strip(), result.stderr.decode(errors='replace')[-400:]
    if result.returncode != 0:
        if _re.search(r'denied|PermissionDenied|cannot open .* service|Cannot open', err, _re.IGNORECASE):
            raise PermissionError('Target account lacks the right for this service action: ' + err[-160:])
        raise ValueError('PowerShell template failed: ' + err[-200:])
    return json.loads(out) if out else None
def service_name():
    name = nparams['service'][:-len('.service')] if nparams['service'].endswith('.service') else nparams['service']
    if not _re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', name): raise ValueError('Invalid Windows service name')
    return name
def service_state(name):
    value = ps("$s = Get-CimInstance Win32_Service -Filter \"Name='" + name + "'\"; if (-not $s) { throw 'service not found' }; "
               "[pscustomobject]@{Id=$s.Name; ActiveState=$s.State; StartMode=$s.StartMode; ServiceType=$s.ServiceType; "
               "ProcessId=[int]$s.ProcessId} | ConvertTo-Json -Compress")
    return value
def read():
    if nested == 'disk.usage':
        rows = ps("ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
                  "ForEach-Object { [pscustomobject]@{mount=$_.DeviceID; size_kb=[int64]($_.Size/1024); avail_kb=[int64]($_.FreeSpace/1024)} })")
        for row in rows: row['use_pct'] = round(100 * (row['size_kb'] - row['avail_kb']) / row['size_kb']) if row['size_kb'] else 0
        return {'filesystems': rows}
    if nested == 'memory.usage':
        m = ps("$o = Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{total_kb=[int64]$o.TotalVisibleMemorySize; "
               "available_kb=[int64]$o.FreePhysicalMemory} | ConvertTo-Json -Compress")
        m['used_pct'] = round(100 * (m['total_kb'] - m['available_kb']) / m['total_kb'], 1)
        return m
    if nested == 'ports.listen':
        ports = ps("ConvertTo-Json -Compress -InputObject @(Get-NetTCPConnection -State Listen | "
                   "Select-Object @{n='address';e={$_.LocalAddress}}, @{n='port';e={[int]$_.LocalPort}} | Select-Object -First 512)")
        wanted = nparams.get('port')
        return {'listening': [p for p in ports if wanted is None or p['port'] == wanted], 'filter': wanted}
    if nested == 'service.status':
        return service_state(service_name())
    raise ValueError('Action not available agentlessly on Windows')
if mode == 'check':
    probe = ps("[pscustomobject]@{os=(Get-CimInstance Win32_OperatingSystem).Caption} | ConvertTo-Json -Compress")
    if nested.startswith('service.'):
        state = service_state(service_name())
        print(json.dumps({'reachable': True, 'os': probe['os'], 'service': state['Id']}))
    else:
        print(json.dumps({'reachable': True, 'os': probe['os']}))
    raise SystemExit(0)
if nested in ('service.start', 'service.stop', 'service.restart'):
    name = service_name(); before = service_state(name)
    if mode == 'apply':
        verb = {'service.start': 'Start-Service', 'service.stop': 'Stop-Service', 'service.restart': 'Restart-Service'}[nested]
        ps(verb + " -Name '" + name + "'", timeout=90)
        deadline = time.monotonic() + 20; after = service_state(name)
        while time.monotonic() < deadline and after['ActiveState'] in ('Start Pending', 'Stop Pending'):
            time.sleep(0.5); after = service_state(name)
        if nested == 'service.restart' and after['ServiceType'] == 'Own Process' and after['ProcessId'] == before['ProcessId']:
            raise ValueError('Service did not restart (process id unchanged)')
    else:
        after = before
    ok = after['ActiveState'] == ('Stopped' if nested == 'service.stop' else 'Running')
    if not ok: raise ValueError('Service postcondition failed: ' + str(after))
    proof = 'process_id_changed' if nested == 'service.restart' and after['ServiceType'] == 'Own Process' else (
        'shared_process_restart_unprovable' if nested == 'service.restart' else None)
    print(json.dumps({'verified': True, 'agentless': True, 'platform': 'windows', 'action': nested, 'before': before,
                      'after': after, 'restart_proof': proof}))
else:
    print(json.dumps({'verified': True, 'agentless': True, 'platform': 'windows', 'action': nested, 'result': read()}))
'''
