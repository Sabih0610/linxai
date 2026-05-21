/* ebpf/probes/execve.c */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct execve_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(execve_events);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {

    struct execve_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid  = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    execve_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
