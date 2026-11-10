"""Capability evidence -> LINxAI feature support (pure standard library).

Shared by the offline knowledge base (public vendor YANG data) and live discovery.
A feature is supported *by model* when every module it writes is advertised and no
vendor `deviate not-supported` covers its target or any leaf it sets. A device
validating an example edit (probe) and a committed lab run are stronger evidence,
recorded separately; a model-level "supported" is a prediction, never a guarantee.
"""
import re
from urllib.parse import parse_qs

from operations import netconf_features as nf

# OpenConfig namespace key -> module that must be advertised; identity-only modules are not required.
MODULES = {"sys": "openconfig-system", "if": "openconfig-interfaces", "ip": "openconfig-if-ip",
           "eth": "openconfig-if-ethernet", "vlan": "openconfig-vlan", "ni": "openconfig-network-instance",
           "lag": "openconfig-if-aggregate", "acl": "openconfig-acl", "qos": "openconfig-qos"}
TYPES = {"pt", "nit", "vt", "bt", "srlif"}
# Schema roots whose deviations can matter for LINxAI features or discovery facts.
RELEVANT_ROOTS = re.compile(r"^/(interfaces|system|network-instances|acl|qos|lldp|components|vlans)(/|$)")
P, P2 = "probe0", "probe1"
SAMPLES = {
    "interface.description": {"interface": P, "description": "linxai probe"}, "system.hostname": {"hostname": "linxai-probe"},
    "system.banner": {"motd": "linxai probe"}, "system.ntp_server": {"address": "192.0.2.123"},
    "system.dns_server": {"address": "192.0.2.53"},
    "interface.ipv4": {"interface": P, "address": "198.51.100.1", "prefix_length": 30}, "vlan": {"vlan_id": 100},
    "interface.access_vlan": {"interface": P, "vlan_id": 100},
    "static_route": {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"}, "ospf.interface": {"interface": P},
    "bgp.global": {"asn": 65001, "router_id": "192.0.2.1"}, "bgp.peer_group": {"name": "linxai-probe", "peer_as": 65002},
    "bgp.neighbor": {"neighbor": "198.51.100.2", "peer_as": 65002}, "lag.member": {"interface": P, "lag": P2},
    "acl.entry": {"acl": "linxai-probe", "sequence": 10, "action": "drop", "destination": "203.0.113.0/24"},
    "qos.queue": {"name": "linxai-q"}, "qos.forwarding_group": {"name": "linxai-fg", "queue": "linxai-q"},
    "qos.classifier_term": {"classifier": "linxai-cls", "term": 1, "dscp": [46], "forwarding_group": "linxai-fg"},
    "qos.interface_classifier": {"interface": P, "classifier": "linxai-cls"},
    "srl.vxlan_interface": {"vni": 100}, "srl.mac_vrf_evpn": {"name": "linxai-probe", "vni": 100, "route_target": "target:65001:100"},
    "srl.qos_queue": {"queue": "unicast-5"}, "srl.qos_forwarding_class": {"name": "fc5", "unicast_queue": "unicast-5"},
    "srl.qos_dscp_rule": {"policy": "linxai-probe", "dscp": 46, "forwarding_class": "fc5"},
    "srl.qos_interface_policy": {"interface": P, "policy": "linxai-probe"}}
SYNTHETIC = {"host": "192.0.2.10", "ports": [P, P2], "features": sorted(nf.FEATURES)}
VENDORS = ((r"^Cisco-IOS-XR-", "cisco", "iosxr"), (r"^Cisco-IOS-XE-", "cisco", "iosxe"), (r"^Cisco-NX-OS-", "cisco", "nxos"),
           (r"^(junos|jnx-)", "juniper", "junos"), (r"^huawei-", "huawei", "vrp"), (r"^srl_nokia-", "nokia", "srlinux"),
           (r"^nokia-(conf|state)", "nokia", "sros"), (r"^arista-", "arista", "eos"), (r"^arrcus-", "arrcus", "arcos"))


def parse_capabilities(lines):
    """NETCONF hello capability URIs -> {module: {namespace, revision, deviations, features}}."""
    modules = {}
    for line in lines:
        uri, _, query = str(line).strip().partition("?")
        q = parse_qs(query)
        name = (q.get("module") or [""])[0]
        if not re.fullmatch(r"[A-Za-z_][\w.-]{0,127}", name):
            continue
        modules[name] = {"namespace": uri[:256], "revision": (q.get("revision") or [""])[0][:16],
                         "deviations": [d for d in ",".join(q.get("deviations", []) + q.get("deviation", [])).split(",") if d][:64],
                         "features": [f for f in ",".join(q.get("features", [])).split(",") if f][:128]}
    return modules


def identify(modules):
    """Vendor and OS family from vendor module names (most votes wins)."""
    votes = {}
    for name in modules:
        for pattern, vendor, family in VENDORS:
            if re.search(pattern, name):
                votes[(vendor, family)] = votes.get((vendor, family), 0) + 1
    return max(votes, key=votes.get) if votes else ("unknown", "unknown")


def _statements(text):
    """Yield (path, body) for each top-level `deviation` statement, matching braces outside strings."""
    for match in re.finditer(r'\bdeviation\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s{;]+))\s*\{', text):
        depth, i, quote = 1, match.end(), None
        while i < len(text) and depth:
            c = text[i]
            if quote:
                quote = None if c == quote else quote
            elif c in "\"'":
                quote = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        yield (match.group(1) or match.group(2) or match.group(3)), text[match.end():i - 1]


def parse_deviations(text, module=""):
    """YANG deviation module text -> [{path (prefix-free tags), deviate kinds, module}]."""
    found = []
    for raw, body in _statements(text):
        tags = tuple(part.split(":")[-1] for part in re.sub(r"\s+", "", raw).strip("/").split("/") if part)
        kinds = sorted(set(re.findall(r"\bdeviate\s+(not-supported|add|replace|delete)\b", body)))
        if tags and kinds:
            found.append({"path": "/" + "/".join(tags), "deviate": kinds, "module": module[:128]})
    return found


def _ns_keys(path, config):
    keys = {element[0] for element in path}
    for element in path:
        if len(element) > 3:
            keys |= _config_ns(element[3], element[0])
    return keys | _config_ns(config, path[-1][0])


def _config_ns(config, ns):
    keys = {ns}
    for key, value in config.items():
        inner = key[1:].split("}")[0] if key.startswith("{") else ns
        keys.add(inner)
        if isinstance(value, dict):
            keys |= _config_ns(value, inner)
    return keys


def leaf_paths(path, config):
    """Every schema leaf a feature writes, as prefix-free tag tuples (keys, parent config, config)."""
    tags, leaves = (), []
    for element in path:
        tags += (element[1],)
        leaves += [tags + (k,) for k in element[2]]
        if len(element) > 3:
            leaves += [tags + rel for rel, _ in nf.expected_leaves(element[3])]
    leaves += [tags + rel for rel, _ in nf.expected_leaves(config)]
    return tags, leaves


def evaluate(feature, modules, deviations, namespaces=None):
    """Model-level support of one feature on a platform.

    modules: advertised module names; namespaces: advertised namespaces (live only, for
    vendor-native features); deviations: parse_deviations() rows."""
    path, config = nf.resolve(feature, SAMPLES[feature], SYNTHETIC)
    target, leaves = leaf_paths(path, config)
    evidence = []
    for key in sorted(_ns_keys(path, config) - TYPES):
        if key in MODULES:
            if MODULES[key] not in modules:
                return {"feature": feature, "status": "unsupported", "evidence": [f"model {MODULES[key]} not advertised"]}
            evidence.append(f"model {MODULES[key]}")
        elif namespaces is None:
            return {"feature": feature, "status": "unknown", "evidence": ["vendor-native model; needs a live device"]}
        elif nf.NS[key] not in namespaces:
            return {"feature": feature, "status": "unsupported", "evidence": [f"namespace {nf.NS[key]} not advertised"]}
        else:
            evidence.append(f"native {nf.NS[key]}")
    limited = []
    for row in deviations:
        dev = tuple(row["path"].strip("/").split("/"))
        if any(leaf[:len(dev)] == dev for leaf in [target, *leaves]):
            if "not-supported" in row["deviate"]:
                return {"feature": feature, "status": "unsupported",
                        "evidence": [f"vendor deviation not-supported {row['path']} ({row['module']})"]}
            limited.append(f"deviation {'/'.join(row['deviate'])} {row['path']}")
    if limited:
        return {"feature": feature, "status": "supported_with_limits", "evidence": evidence + limited[:8]}
    return {"feature": feature, "status": "supported", "evidence": evidence}


def evaluate_all(modules, deviations, namespaces=None):
    return [evaluate(feature, modules, deviations, namespaces) for feature in sorted(nf.FEATURES)]
