"""Declarative catalog of typed NETCONF/OpenConfig configuration features.

Pure standard library: the contract layer imports it to validate settings, and the
fixed device worker embeds this source to build, read, verify and restore changes.
Each feature names ONE target node (an OpenConfig container or list entry) and the
config written under it. The generic engine snapshots the target before a change,
merges the desired config, verifies every desired leaf by read-back, and restores by
replacing the target with its snapshot (or removing it if it did not exist).
Guards refuse changes that could cut the device off from management.
"""
import ipaddress
import re
from xml.sax.saxutils import escape

NS = {"sys": "http://openconfig.net/yang/system", "if": "http://openconfig.net/yang/interfaces",
      "ip": "http://openconfig.net/yang/interfaces/ip", "eth": "http://openconfig.net/yang/interfaces/ethernet",
      "vlan": "http://openconfig.net/yang/vlan", "ni": "http://openconfig.net/yang/network-instance",
      "pt": "http://openconfig.net/yang/policy-types", "lag": "http://openconfig.net/yang/interfaces/aggregate",
      "acl": "http://openconfig.net/yang/acl", "nit": "http://openconfig.net/yang/network-instance-types",
      "vt": "http://openconfig.net/yang/vlan-types", "bt": "http://openconfig.net/yang/bgp-types",
      "qos": "http://openconfig.net/yang/qos",
      # Nokia SR Linux native models (EVPN-VXLAN is not-supported in its OpenConfig deviations)
      "srlvx": "urn:nokia.com:srlinux:vxlan:tunnel-interfaces", "srlif": "urn:nokia.com:srlinux:chassis:interfaces",
      "srlni": "urn:nokia.com:srlinux:net-inst:network-instance", "srlevpn": "urn:nokia.com:srlinux:net-inst:bgp-evpn",
      "srlvpn": "urn:nokia.com:srlinux:bgp:bgp-vpn", "srlqos": "urn:nokia.com:srlinux:qos:qos"}
# Conventional module prefixes; some devices only accept identityref values with these.
PREFIX = {NS["pt"]: "oc-pol-types", NS["acl"]: "oc-acl", NS["nit"]: "oc-ni-types", NS["vt"]: "oc-vlan-types", NS["bt"]: "oc-bgp-types",
          NS["srlif"]: "srl_nokia-interfaces"}
NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
IFACE = re.compile(r"[A-Za-z][A-Za-z0-9_./:-]{0,31}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")


class Identity(str):
    """An identityref value: rendered with a namespace prefix, compared by local name."""
    def __new__(cls, ns, name):
        value = super().__new__(cls, name); value.ns = ns; return value


def _ip(value):
    return str(ipaddress.ip_address(value))


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"integer {low}..{high} required")
    return value


def _text(value, limit):
    if not isinstance(value, str) or len(value) > limit or not value.isprintable():
        raise ValueError(f"printable text up to {limit} characters required")
    return value


def _iface(value, asset):
    if not isinstance(value, str) or not IFACE.fullmatch(value) or value not in asset["ports"]:
        raise ValueError("interface must be on the asset's allowlist")
    return value


def _ni(s):
    name = s.get("network_instance", "default")
    if not NAME.fullmatch(str(name)):
        raise ValueError("invalid network instance")
    return name


def _mgmt_safe(network, asset):
    """Refuse prefixes that contain the device's management address."""
    try:
        mgmt = ipaddress.ip_address(asset["host"])
    except ValueError:
        return                     # hostname: the worker re-checks with the resolved address
    if mgmt.version == network.version and mgmt in network:
        raise ValueError("change would affect the device's management address")


def _protocol(kind, s, asset):
    name = _pname(s, kind, asset)
    return [("ni", "network-instances", {}), _instance(s),
            ("ni", "protocols", {}), ("ni", "protocol", {"identifier": Identity(NS["pt"], kind), "name": name},
                                       {"config": {"identifier": Identity(NS["pt"], kind), "name": name}})]


PROTOCOL_KINDS = ("STATIC", "OSPF", "BGP")


def _pname(s, kind, asset):
    """Protocol instance name: the request, else the device's convention found by discovery
    (asset `protocol_names`, e.g. IOS XR's static instance is `DEFAULT`), else the OpenConfig default."""
    name = s.get("protocol_name") or (asset.get("protocol_names") or {}).get(kind) or {"STATIC": "static"}.get(kind, kind)
    if not NAME.fullmatch(str(name)):
        raise ValueError("invalid protocol instance name")
    return name


def _instance(s):
    name = _ni(s)
    kind = "DEFAULT_INSTANCE" if name == "default" else "L3VRF"
    return ("ni", "network-instance", {"name": name}, {"config": {"name": name, "type": Identity(NS["nit"], kind)}})


# feature -> validate(settings, asset) returning (path, config). A path is a list of
# (namespace, tag, keys); keys are rendered as leaves of that list entry.
def interface_description(s, asset):
    name = _iface(s["interface"], asset)
    return [("if", "interfaces", {}), ("if", "interface", {"name": name}), ("if", "config", {})], \
        {"name": name, "description": _text(s["description"], 80)}


def system_hostname(s, asset):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", str(s["hostname"])):
        raise ValueError("hostname must be letters, digits and hyphens")
    return [("sys", "system", {}), ("sys", "config", {})], {"hostname": s["hostname"]}


def system_banner(s, asset):
    return [("sys", "system", {}), ("sys", "config", {})], {"motd-banner": _text(s["motd"], 200)}


def system_ntp_server(s, asset):
    address = _ip(s["address"])
    return [("sys", "system", {}), ("sys", "ntp", {}), ("sys", "servers", {}), ("sys", "server", {"address": address})], \
        {"config": {"address": address}}


def system_dns_server(s, asset):
    address = _ip(s["address"])
    return [("sys", "system", {}), ("sys", "dns", {}), ("sys", "servers", {}), ("sys", "server", {"address": address})], \
        {"config": {"address": address}}


def interface_ipv4(s, asset):
    name = _iface(s["interface"], asset)
    network = ipaddress.ip_interface(f"{_ip(s['address'])}/{_int(s['prefix_length'], 1, 31)}")
    if network.version != 4:
        raise ValueError("IPv4 address required")
    _mgmt_safe(network.network, asset)
    return [("if", "interfaces", {}), ("if", "interface", {"name": name}), ("if", "subinterfaces", {}),
            ("if", "subinterface", {"index": 0}, {"config": {"index": 0}}), ("ip", "ipv4", {}), ("ip", "addresses", {}),
            ("ip", "address", {"ip": str(network.ip)})], \
        {"config": {"ip": str(network.ip), "prefix-length": network.network.prefixlen}}


def vlan(s, asset):
    vid = _int(s["vlan_id"], 2, 4094)
    return [("ni", "network-instances", {}), _instance(s), ("ni", "vlans", {}),
            ("ni", "vlan", {"vlan-id": vid})], {"config": {"vlan-id": vid, "name": _text(s.get("name", f"vlan{vid}"), 32)}}


def interface_access_vlan(s, asset):
    name = _iface(s["interface"], asset)
    return [("if", "interfaces", {}), ("if", "interface", {"name": name}), ("eth", "ethernet", {}),
            ("vlan", "switched-vlan", {}), ("vlan", "config", {})], \
        {"interface-mode": Identity(NS["vt"], "ACCESS"), "access-vlan": _int(s["vlan_id"], 2, 4094)}


def static_route(s, asset):
    prefix = ipaddress.ip_network(str(s["prefix"]), strict=True)
    if prefix.prefixlen == 0:
        raise ValueError("default routes are refused; they can capture management traffic")
    _mgmt_safe(prefix, asset)
    hop = ipaddress.ip_address(s["next_hop"])
    if hop.is_loopback or hop.is_unspecified or hop.version != prefix.version:
        raise ValueError("next hop must be a routable address of the same family")
    return _protocol("STATIC", s, asset) + [("ni", "static-routes", {}), ("ni", "static", {"prefix": str(prefix)})], \
        {"config": {"prefix": str(prefix)},
         "next-hops": {"next-hop": {"index": "1", "config": {"index": "1", "next-hop": str(hop)}}}}


def ospf_interface(s, asset):
    name = _iface(s["interface"], asset)
    area = str(ipaddress.ip_address(s.get("area", "0.0.0.0")))
    return _protocol("OSPF", s, asset) + [("ni", "ospfv2", {}), ("ni", "areas", {}), ("ni", "area", {"identifier": area}),
                                   ("ni", "interfaces", {}), ("ni", "interface", {"id": name})], \
        {"config": {"id": name, **({"passive": bool(s["passive"])} if "passive" in s else {})}}


def bgp_global(s, asset):
    config = {"as": _int(s["asn"], 1, 4294967295)}
    if s.get("router_id"):
        config["router-id"] = str(ipaddress.IPv4Address(s["router_id"]))
    v4 = Identity(NS["bt"], "IPV4_UNICAST")      # some devices (SR Linux) need an enabled address family
    return _protocol("BGP", s, asset) + [("ni", "bgp", {}), ("ni", "global", {})],         {"config": config, "afi-safis": {"afi-safi": {"afi-safi-name": v4, "config": {"afi-safi-name": v4, "enabled": True}}}}


def bgp_peer_group(s, asset):
    name = s["name"] if isinstance(s.get("name"), str) and NAME.fullmatch(s["name"]) else None
    if not name:
        raise ValueError("peer group name required")
    config = {"peer-group-name": name}
    if s.get("peer_as") is not None:
        config["peer-as"] = _int(s["peer_as"], 1, 4294967295)
    return _protocol("BGP", s, asset) + [("ni", "bgp", {}), ("ni", "peer-groups", {}), ("ni", "peer-group", {"peer-group-name": name})],         {"config": config}


def bgp_neighbor(s, asset):
    neighbor = _ip(s["neighbor"])
    _mgmt_safe(ipaddress.ip_network(neighbor), asset)
    return _protocol("BGP", s, asset) + [("ni", "bgp", {}), ("ni", "neighbors", {}), ("ni", "neighbor", {"neighbor-address": neighbor})], \
        {"config": {"neighbor-address": neighbor, "peer-as": _int(s["peer_as"], 1, 4294967295),
                    **({"peer-group": s["peer_group"]} if isinstance(s.get("peer_group"), str) and NAME.fullmatch(s["peer_group"]) else {})}}


def lag_member(s, asset):
    name, lag = _iface(s["interface"], asset), _iface(s["lag"], asset)
    if name == lag:
        raise ValueError("interface cannot be its own aggregate")
    return [("if", "interfaces", {}), ("if", "interface", {"name": name}), ("eth", "ethernet", {}), ("eth", "config", {})], \
        {"{lag}aggregate-id": lag}


def acl_entry(s, asset):
    action = {"accept": "ACCEPT", "permit": "ACCEPT", "allow": "ACCEPT", "drop": "DROP", "deny": "DROP", "block": "DROP",
              "reject": "REJECT"}[str(s["action"]).lower()]
    src, dst = ipaddress.ip_network(str(s.get("source", "0.0.0.0/0"))), ipaddress.ip_network(str(s.get("destination", "0.0.0.0/0")))
    if action != "ACCEPT":
        _mgmt_safe(dst, asset)        # a drop rule may never match traffic to the management address
    ipv4 = {"source-address": str(src), "destination-address": str(dst)}
    if s.get("protocol") is not None:
        ipv4["protocol"] = _int(s["protocol"], 1, 255)
    name = s["acl"] if isinstance(s.get("acl"), str) and NAME.fullmatch(s["acl"]) else None
    if not name:
        raise ValueError("ACL name required")
    seq = _int(s["sequence"], 1, 65535)
    return [("acl", "acl", {}), ("acl", "acl-sets", {}), ("acl", "acl-set", {"name": name, "type": Identity(NS["acl"], "ACL_IPV4")},
             {"config": {"name": name, "type": Identity(NS["acl"], "ACL_IPV4")}}),
            ("acl", "acl-entries", {}), ("acl", "acl-entry", {"sequence-id": seq})], \
        {"config": {"sequence-id": seq}, "ipv4": {"config": ipv4},
         "actions": {"config": {"forwarding-action": Identity(NS["acl"], action)}}}


def _name(s, key, what):
    value = s.get(key)
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(f"{what} name required")
    return value


def qos_queue(s, asset):
    name = _name(s, "name", "queue")
    return [("qos", "qos", {}), ("qos", "queues", {}), ("qos", "queue", {"name": name})], {"config": {"name": name}}


def qos_forwarding_group(s, asset):
    name, queue = _name(s, "name", "forwarding group"), _name(s, "queue", "output queue")
    return [("qos", "qos", {}), ("qos", "forwarding-groups", {}), ("qos", "forwarding-group", {"name": name})],         {"config": {"name": name, "output-queue": queue}}


def qos_classifier_term(s, asset):
    name, group = _name(s, "classifier", "classifier"), _name(s, "forwarding_group", "forwarding group")
    dscp = s["dscp"]
    if not isinstance(dscp, list) or not 1 <= len(dscp) <= 8 or len(set(dscp)) != len(dscp):
        raise ValueError("dscp must be a list of 1-8 distinct values")
    term = str(_int(s["term"], 1, 65535))
    return [("qos", "qos", {}), ("qos", "classifiers", {}),
            ("qos", "classifier", {"name": name}, {"config": {"name": name, "type": "IPV4"}}),
            ("qos", "terms", {}), ("qos", "term", {"id": term})],         {"config": {"id": term}, "conditions": {"ipv4": {"config": {"dscp-set": sorted(_int(d, 0, 63) for d in dscp)}}},
         "actions": {"config": {"target-group": group}}}


def qos_interface_classifier(s, asset):
    name, classifier = _iface(s["interface"], asset), _name(s, "classifier", "classifier")
    return [("qos", "qos", {}), ("qos", "interfaces", {}),
            ("qos", "interface", {"interface-id": name}, {"config": {"interface-id": name}}),
            ("qos", "input", {}), ("qos", "classifiers", {}), ("qos", "classifier", {"type": "IPV4"})],         {"config": {"type": "IPV4", "name": classifier}}


def _vni(s):
    tunnel = s.get("tunnel", "vxlan1")
    if not isinstance(tunnel, str) or not re.fullmatch(r"vxlan(25[0-5]|2[0-4]\d|1?\d?\d)", tunnel):
        raise ValueError("tunnel must be vxlan0..vxlan255")
    return tunnel, _int(s["vni"], 1, 16777215)


def srl_vxlan_interface(s, asset):
    """SR Linux native: a bridged VXLAN interface <tunnel>.<vni>."""
    tunnel, vni = _vni(s)
    return [("srlvx", "tunnel-interface", {"name": tunnel}), ("srlvx", "vxlan-interface", {"index": vni})],         {"type": Identity(NS["srlif"], "bridged"), "ingress": {"vni": vni}}


def srl_mac_vrf_evpn(s, asset):
    """SR Linux native: an EVPN-VXLAN MAC-VRF bound to <tunnel>.<vni> with one route target."""
    name = _name(s, "name", "MAC-VRF")
    if name in ("default", "mgmt"):
        raise ValueError("the default and management instances cannot be changed")
    tunnel, vni = _vni(s)
    rt = s["route_target"]
    if not isinstance(rt, str) or not re.fullmatch(r"target:\d{1,10}:\d{1,10}", rt):
        raise ValueError("route target must look like target:65001:100")
    vxi = f"{tunnel}.{vni}"
    return [("srlni", "network-instance", {"name": name})],         {"type": "mac-vrf", "admin-state": "enable", "vxlan-interface": {"name": vxi},
         "protocols": {"bgp-evpn": {"{srlevpn}bgp-instance": {"id": 1, "admin-state": "enable", "vxlan-interface": vxi,
                                                              "evi": _int(s.get("evi", vni if vni <= 65535 else 0), 1, 65535)}},
                       "{srlvpn}bgp-vpn": {"bgp-instance": {"id": 1, "route-target": {"export-rt": rt, "import-rt": rt}}}}}


# SR Linux QoS is native-only in practice: its OpenConfig translation needs a queue-index
# that OpenConfig cannot express. Classes fc0-fc7 and queues unicast-0..7 are fixed.
def _pick(s, key, pattern, what):
    value = s.get(key)
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError(f"{what} required")
    return value


def srl_qos_queue(s, asset):
    queue = _pick(s, "queue", r"(unicast|multicast)-[0-7]", "queue unicast-0..7 or multicast-0..7")
    return [("srlqos", "qos", {}), ("srlqos", "queues", {}), ("srlqos", "queue", {"name": queue})], {"queue-index": int(queue[-1])}


def srl_qos_forwarding_class(s, asset):
    name = _pick(s, "name", r"fc[0-7]", "forwarding class fc0..fc7")
    queue = _pick(s, "unicast_queue", r"unicast-[0-7]", "unicast queue unicast-0..7")
    return [("srlqos", "qos", {}), ("srlqos", "forwarding-classes", {}), ("srlqos", "forwarding-class", {"name": name})], \
        {"output": {"unicast-queue": queue}}


def srl_qos_dscp_rule(s, asset):
    policy, dscp = _name(s, "policy", "DSCP policy"), _int(s["dscp"], 0, 63)
    fc = _pick(s, "forwarding_class", r"fc[0-7]", "forwarding class fc0..fc7")
    return [("srlqos", "qos", {}), ("srlqos", "classifiers", {}), ("srlqos", "dscp-policy", {"name": policy}),
            ("srlqos", "dscp", {"value": dscp})], {"forwarding-class": fc}


def srl_qos_interface_policy(s, asset):
    name, policy = _iface(s["interface"], asset), _name(s, "policy", "DSCP policy")
    ident = "linxai-" + re.sub(r"[^A-Za-z0-9]", "-", name)
    return [("srlqos", "qos", {}), ("srlqos", "interfaces", {}), ("srlqos", "interface", {"interface-id": ident})], \
        {"interface-ref": {"interface": name, "subinterface": 0}, "input": {"classifiers": {"dscp-policy": policy}}}


FEATURES = {"interface.description": interface_description, "system.hostname": system_hostname,
            "system.banner": system_banner, "system.ntp_server": system_ntp_server, "system.dns_server": system_dns_server,
            "interface.ipv4": interface_ipv4, "vlan": vlan, "interface.access_vlan": interface_access_vlan,
            "static_route": static_route, "ospf.interface": ospf_interface, "bgp.global": bgp_global, "bgp.peer_group": bgp_peer_group, "bgp.neighbor": bgp_neighbor,
            "lag.member": lag_member, "acl.entry": acl_entry,
            "qos.queue": qos_queue, "qos.forwarding_group": qos_forwarding_group,
            "qos.classifier_term": qos_classifier_term, "qos.interface_classifier": qos_interface_classifier,
            "srl.vxlan_interface": srl_vxlan_interface, "srl.mac_vrf_evpn": srl_mac_vrf_evpn,
            "srl.qos_queue": srl_qos_queue, "srl.qos_forwarding_class": srl_qos_forwarding_class,
            "srl.qos_dscp_rule": srl_qos_dscp_rule, "srl.qos_interface_policy": srl_qos_interface_policy}


def resolve(feature, settings, asset):
    """Validate settings for a feature allowed on this asset; returns (path, config)."""
    if feature not in FEATURES or feature not in asset.get("features", ()):
        raise ValueError("feature not enabled for this asset")
    if not isinstance(settings, dict) or len(settings) > 12:
        raise ValueError("settings object required")
    try:
        return FEATURES[feature](settings, asset)
    except KeyError as exc:
        raise ValueError(f"missing setting {exc}") from None
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from None


def _tag(ns_key, tag, parent_ns):
    ns = NS[ns_key]
    return tag, (f' xmlns="{ns}"' if ns != parent_ns else ""), ns


def _leaf(name, value, ns):
    if isinstance(value, Identity):
        if value.ns == ns:              # RFC 7950: an unprefixed identity resolves to the element's module
            return f"<{name}>{escape(str(value))}</{name}>"
        prefix = PREFIX.get(value.ns, "x")
        return f'<{name} xmlns:{prefix}="{value.ns}">{prefix}:{escape(str(value))}</{name}>'
    if isinstance(value, bool):
        value = "true" if value else "false"
    return f"<{name}>{escape(str(value))}</{name}>"


def _body(config, ns):
    out = []
    for key, value in config.items():
        if key.startswith("{"):
            ns_key, name = key[1:].split("}")
            inner = _body(value, NS[ns_key]) if isinstance(value, dict) else escape(str(value))
            out.append(f'<{name} xmlns="{NS[ns_key]}">{inner}</{name}>')
        elif isinstance(value, dict):
            out.append(f"<{key}>{_body(value, ns)}</{key}>")
        elif isinstance(value, list):                 # YANG leaf-list
            out.extend(_leaf(key, item, ns) for item in value)
        else:
            out.append(_leaf(key, value, ns))
    return "".join(out)


def render(path, config=None, operation=None, inner_xml=None, extra=""):
    """XML for a path: keys only (filter), desired config (merge), or an operation."""
    opens, closes, parent = [], [], None
    for index, (ns_key, tag, keys, *extra_cfg) in enumerate(path):
        name, decl, parent = (*_tag(ns_key, tag, parent),)
        last = index == len(path) - 1
        attr = f' xmlns:nc="{NC}" nc:operation="{operation}"{extra}' if last and operation else ""
        key_xml = "" if last and inner_xml is not None else "".join(_leaf(k, v, parent) for k, v in keys.items())
        parent_cfg = _body(extra_cfg[0], parent) if extra_cfg and config and not last else ""
        opens.append(f"<{name}{decl}{attr}>" + key_xml + parent_cfg)
        closes.insert(0, f"</{name}>")
    body = inner_xml if inner_xml is not None else (_body(config, parent) if config else "")
    return "".join(opens) + body + "".join(closes)


def expected_leaves(config, prefix=()):
    """Flatten desired config into (relative tag path, value) pairs for read-back checks."""
    for key, value in config.items():
        name = key.split("}")[-1]
        if isinstance(value, dict):
            yield from expected_leaves(value, prefix + (name,))
        elif isinstance(value, list):
            for item in value:
                yield prefix + (name,), str(item)
        else:
            yield prefix + (name,), ("true" if value is True else "false" if value is False else str(value))
