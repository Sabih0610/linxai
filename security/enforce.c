#include <uapi/linux/in.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <net/sock.h>
struct key_t { u32 uid; u32 addr; u16 port; u16 pad; };
struct value_t { u64 expires_ns; u64 token; };
BPF_HASH(blocks, struct key_t, struct value_t, 64);
BPF_HASH(denied, struct key_t, u64, 64);
/* Preserve previous LSM decisions. Empty/expired maps never deny. */
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    if (ret) return ret;
    if (addrlen < sizeof(struct sockaddr_in)) return 0;
    struct sockaddr_in sin = {};
    bpf_probe_read_kernel(&sin, sizeof(sin), address);
    if (sin.sin_family != AF_INET) return 0;
    /* Restrict to stream TCP sockets, not UDP or other socket protocols. */
    if (sock->type != SOCK_STREAM) return 0;
    if (!sock->sk || sock->sk->sk_protocol != IPPROTO_TCP) return 0;
    struct key_t key = {};
    key.uid = bpf_get_current_uid_gid() & 0xffffffff;
    key.addr = sin.sin_addr.s_addr;
    key.port = __builtin_bswap16(sin.sin_port);
    struct value_t *value = blocks.lookup(&key);
    if (!value || bpf_ktime_get_boot_ns() >= value->expires_ns) return 0;
    denied.increment(key);
    return -EPERM;
}
