/* ebpf/probes/execve.c */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct execve_event_t {
    u64 monotonic_ns;
    u64 start_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(execve_events);

int trace_execve(struct pt_regs *ctx) {

    struct execve_event_t event = {};
    event.monotonic_ns = bpf_ktime_get_ns();
    struct task_struct *leader = ((struct task_struct *)bpf_get_current_task())->group_leader;
    event.start_ns = leader->start_time;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid  = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    /* x86_64 syscall wrapper: real arguments are in nested syscall registers. */
    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);
    u64 filename_ptr = 0;
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &inner->di);
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), (void *)filename_ptr);

    execve_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
