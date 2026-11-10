"""Read-only NETCONF device discovery (device.discover), embedded in the NETCONF worker.

Collects what a device reports about itself: the hello capability list, the vendor
deviation modules named in it, OpenConfig system/platform/interface/LLDP state, and a
fingerprint (never the content) of the running configuration, which can hold secrets.
Raw replies are returned compressed with their SHA-256 for the bronze layer; parsing
happens outside the worker. Nothing is written to the device.
"""

DISCOVER_CODE = r'''
import zlib as _zlib
DISCOVERY_BUDGET_S = 20
def _pack(name, text):
    raw = text.encode()
    return {'name': name, 'ok': True, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'z': base64.b64encode(_zlib.compress(raw, 9)).decode()}
def discover_main(m):
    started, items = time.time(), []
    caps = sorted(str(c) for c in m.server_capabilities)
    items.append(_pack('hello', '\n'.join(caps)))
    if mode != 'apply':                        # check/verify: identity (pinned key) and reachability only
        print(json.dumps({'verified': True, 'platform': 'netconf', 'capabilities': len(caps)})); return
    reads = (('system', '<system xmlns="http://openconfig.net/yang/system"><state/></system>'),
             ('components', '<components xmlns="http://openconfig.net/yang/platform"><component><name/><state/></component></components>'),
             ('interfaces', '<interfaces xmlns="%s"><interface><name/><state/></interface></interfaces>' % OC),
             ('lldp', '<lldp xmlns="http://openconfig.net/yang/lldp"><interfaces/></lldp>'))
    for name, filt in reads:
        try: items.append(_pack(name, m.get(filter=('subtree', filt)).data_xml))
        except Exception as exc: items.append({'name': name, 'ok': False, 'error': str(exc)[:300]})
    try:
        cfg = m.get_config(source='running').data_xml.encode()
        items.append({'name': 'running_config', 'ok': True, 'sha256': hashlib.sha256(cfg).hexdigest(), 'bytes': len(cfg)})
    except Exception as exc:
        items.append({'name': 'running_config', 'ok': False, 'error': str(exc)[:300]})
    wanted = set(NS.values())                  # deviations that can affect LINxAI features
    names = sorted({d for c in caps if c.split('?')[0] in wanted
                    for key in ('deviations=', 'deviation=') if key in c
                    for d in c.split(key, 1)[1].split('&')[0].split(',') if _re.fullmatch(r'[A-Za-z_][\w.-]{0,127}', d)})
    for name in names[:16]:
        if time.time() - started > DISCOVERY_BUDGET_S:
            items.append({'name': 'schema:' + name, 'ok': False, 'error': 'discovery time budget reached'}); continue
        try: items.append(_pack('schema:' + name, m.get_schema(name).data))
        except Exception as exc: items.append({'name': 'schema:' + name, 'ok': False, 'error': str(exc)[:300]})
    print(json.dumps({'verified': True, 'platform': 'netconf', 'discovery': items}))
'''
