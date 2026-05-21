/* ebpf/probes/connect.c */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>

struct connect_event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    u32  dest_ip;
    u16  dest_port;
    u16  family;
};

BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx) {

    struct connect_event_t event = {};
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
    }

    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
