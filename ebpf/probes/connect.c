/* ebpf/probes/connect.c */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>

struct connect_event_t {
    u8 protocol;
    u64 monotonic_ns;
    u64 start_ns;
    u32  pid;
    u32  uid;
    char comm[16];
    u32  dest_ip;
    u16  dest_port;
    u16  family;
    u8   dest_ip6[16];   /* AF_INET6 destination (13 Nov 2026) */
};

BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx) {

    struct connect_event_t event = {};
    event.monotonic_ns = bpf_ktime_get_ns();
    struct task_struct *leader = ((struct task_struct *)bpf_get_current_task())->group_leader;
    event.start_ns = leader->start_time;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* x64 syscall wrapper stores real args in nested pt_regs at ctx->di */
    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);

    u64 addr_ptr = 0;
    bpf_probe_read_kernel(&addr_ptr, sizeof(addr_ptr), &inner->si);

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)addr_ptr);
    event.family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), (void *)addr_ptr);
        event.dest_ip   = sin.sin_addr.s_addr;
        event.dest_port = __builtin_bswap16(sin.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)addr_ptr);
        event.dest_port = __builtin_bswap16(sin6.sin6_port);
        __builtin_memcpy(event.dest_ip6, &sin6.sin6_addr, sizeof(event.dest_ip6));
    }

    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

/* A second, TCP-specific kernel hook supplies protocol provenance. */
int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *address, int addrlen) {
    struct connect_event_t event = {};
    struct sockaddr_in sin = {};
    if (addrlen < sizeof(sin)) return 0;
    bpf_probe_read_kernel(&sin, sizeof(sin), address);
    if (sin.sin_family != AF_INET) return 0;
    event.protocol = IPPROTO_TCP;
    event.monotonic_ns = bpf_ktime_get_ns();
    struct task_struct *leader = ((struct task_struct *)bpf_get_current_task())->group_leader;
    event.start_ns = leader->start_time;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.family = AF_INET;
    event.dest_ip = sin.sin_addr.s_addr;
    event.dest_port = __builtin_bswap16(sin.sin_port);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

/* IPv6 counterpart: TCP provenance for AF_INET6 connections. A v4-mapped destination is
   handed to tcp_v4_connect by the kernel and also reported by the hook above. */
int trace_tcp_v6_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *address, int addrlen) {
    struct connect_event_t event = {};
    struct sockaddr_in6 sin6 = {};
    if (addrlen < sizeof(sin6)) return 0;
    bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
    if (sin6.sin6_family != AF_INET6) return 0;
    event.protocol = IPPROTO_TCP;
    event.monotonic_ns = bpf_ktime_get_ns();
    struct task_struct *leader = ((struct task_struct *)bpf_get_current_task())->group_leader;
    event.start_ns = leader->start_time;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.family = AF_INET6;
    event.dest_port = __builtin_bswap16(sin6.sin6_port);
    __builtin_memcpy(event.dest_ip6, &sin6.sin6_addr, sizeof(event.dest_ip6));
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
