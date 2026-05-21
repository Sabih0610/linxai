/* ebpf/probes/openat.c */

#include <uapi/linux/ptrace.h>

struct openat_event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    char filename[128];
    int  flags;
};

BPF_PERF_OUTPUT(openat_events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct openat_event_t event = {};

    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = args->flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    openat_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
