/* ebpf/probes/openat.c */

#include <uapi/linux/ptrace.h>

struct openat_event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    char filename[128];
    int  flags;
};

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define FILENAME_LEN 128
#define MAX_MATCH_LEN 16

BPF_PERF_OUTPUT(openat_events);

static __always_inline int starts_with_bytes(char *path, char *prefix, int prefix_len) {
#pragma unroll
    for (int i = 0; i < MAX_MATCH_LEN; i++) {
        if (i >= prefix_len) {
            return 1;
        }
        if (path[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

static __always_inline int starts_with_at(char *path, int offset, char *needle, int needle_len) {
#pragma unroll
    for (int i = 0; i < MAX_MATCH_LEN; i++) {
        if (i >= needle_len) {
            return 1;
        }
        if (offset + i >= FILENAME_LEN) {
            return 0;
        }
        if (path[offset + i] != needle[i]) {
            return 0;
        }
    }
    return 1;
}

static __always_inline int contains_bytes(char *path, char *needle, int needle_len) {
#pragma unroll
    for (int i = 0; i < FILENAME_LEN; i++) {
        if (path[i] == '\0') {
            return 0;
        }
        if (starts_with_at(path, i, needle, needle_len)) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_sensitive_path(char *path) {
    char shadow[] = "/etc/shadow";
    char sudoers[] = "/etc/sudoers";
    char proc_keys[] = "/proc/keys";
    char id_rsa[] = "id_rsa";
    char authorized_keys[] = "authorized_keys";

    if (starts_with_bytes(path, shadow, 11)) {
        return 1;
    }
    if (starts_with_bytes(path, sudoers, 12)) {
        return 1;
    }
    if (starts_with_bytes(path, proc_keys, 10)) {
        return 1;
    }
    if (contains_bytes(path, id_rsa, 6)) {
        return 1;
    }
    if (contains_bytes(path, authorized_keys, 15)) {
        return 1;
    }
    return 0;
}

static __always_inline int should_skip_path(char *path) {
    char proc[] = "/proc";
    char sys[] = "/sys";
    char usr_lib[] = "/usr/lib";
    char usr_share[] = "/usr/share";
    char lib[] = "/lib";
    char snap[] = "/snap";
    char cache[] = "/.cache/";
    char locale[] = "/locale";

    if (starts_with_bytes(path, proc, 5)) {
        return 1;
    }
    if (starts_with_bytes(path, sys, 4)) {
        return 1;
    }
    if (starts_with_bytes(path, usr_lib, 8)) {
        return 1;
    }
    if (starts_with_bytes(path, usr_share, 10)) {
        return 1;
    }
    if (starts_with_bytes(path, lib, 4)) {
        return 1;
    }
    if (starts_with_bytes(path, snap, 5)) {
        return 1;
    }
    if (contains_bytes(path, cache, 8)) {
        return 1;
    }
    if (contains_bytes(path, locale, 7)) {
        return 1;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct openat_event_t event = {};

    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = args->flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    if (is_sensitive_path(event.filename)) {
        openat_events.perf_submit(args, &event, sizeof(event));
        return 0;
    }

    if (should_skip_path(event.filename)) {
        return 0;
    }

    openat_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
