#include <linux/bpf.h>
#include <linux/types.h>
#include "bpf_helpers.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * NexisCore Anti-Tamper eBPF Probes
 * Monitors sandboxed agent processes for:
 *   Type 3 — PTRACE_ATTACH attempts (debugger attachment)
 *   Type 4 — mprotect(PROT_WRITE|PROT_EXEC) calls (JIT injection / shellcode)
 *   Type 5 — execve("/bin/sh" or "/bin/bash") from sandboxed PID (shell spawn)
 *
 * On detection: sends SIGKILL to the offending thread and writes a
 * security_event_t into the shared anti_tamper_events ring buffer.
 * ──────────────────────────────────────────────────────────────────────────── */

/* PTRACE_ATTACH request constant */
#define PTRACE_ATTACH 16

/* mprotect protection flags */
#define PROT_WRITE 0x02
#define PROT_EXEC  0x04

/* Anti-tamper breach type constants */
#define BREACH_PTRACE_ATTACH  3
#define BREACH_MPROTECT_WX    4
#define BREACH_SHELL_SPAWN    5

/* ─────────────────────────────────────────────────────────────────────────────
 * Shared Maps (declared extern — populated by the existing monitor.o controller)
 * These maps are pinned by the primary controller; we reuse them here so that
 * the antitamper probes share the same locked_sandboxes membership set.
 * ──────────────────────────────────────────────────────────────────────────── */

/* BPF Hash Map of locked sandbox PIDs — shared with firewall.bpf.c */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} locked_sandboxes SEC(".maps");

/* ─────────────────────────────────────────────────────────────────────────────
 * Anti-tamper dedicated ring buffer (16 MB)
 * ──────────────────────────────────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} anti_tamper_events SEC(".maps");

/* ─────────────────────────────────────────────────────────────────────────────
 * Anti-tamper event structure
 * ──────────────────────────────────────────────────────────────────────────── */
typedef struct {
    __u32 pid;
    __u32 tgid;
    __u32 breach_type;  /* 3=ptrace, 4=mprotect_wx, 5=shell_spawn */
    __u32 target_pid;   /* Populated for ptrace: the victim PID */
    char  comm[16];     /* Task comm name */
} __attribute__((packed)) anti_tamper_event_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Syscall argument contexts
 * ──────────────────────────────────────────────────────────────────────────── */

struct ptrace_args {
    unsigned long long unused;
    long request;
    long pid;           /* pid_t target */
    unsigned long addr;
    unsigned long data;
};

struct mprotect_args {
    unsigned long long unused;
    unsigned long start;
    __kernel_size_t   len;
    unsigned long     prot;
};

struct execve_args {
    unsigned long long unused;
    const char        *filename;
    const char *const *argv;
    const char *const *envp;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: emit an anti-tamper event to the ring buffer and kill the caller.
 * Inlined to minimise instruction count within each tracepoint.
 * ──────────────────────────────────────────────────────────────────────────── */
static __always_inline void emit_and_kill(__u32 pid, __u32 tgid, __u32 breach_type, __u32 target_pid) {
    anti_tamper_event_t *evt = bpf_ringbuf_reserve(&anti_tamper_events, sizeof(anti_tamper_event_t), 0);
    if (evt) {
        evt->pid         = pid;
        evt->tgid        = tgid;
        evt->breach_type = breach_type;
        evt->target_pid  = target_pid;
        bpf_get_current_comm(evt->comm, sizeof(evt->comm));
        bpf_ringbuf_submit(evt, 0);
    }
    /* Terminate the offending thread immediately */
    bpf_send_signal(9); /* SIGKILL */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Probe 1: PTRACE_ATTACH detection
 *
 * Fires on every ptrace(2) syscall entry. If the calling PID is registered in
 * locked_sandboxes and the request is PTRACE_ATTACH (16), we emit an event and
 * send SIGKILL to prevent the debugger from attaching to the attestation engine.
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct ptrace_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)(pid_tgid & 0xFFFFFFFF);

    /* Only intercept calls from locked sandbox PIDs */
    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (!flag || *flag == 0)
        return 0;

    /* Intercept PTRACE_ATTACH requests */
    if (ctx->request == PTRACE_ATTACH) {
        __u32 target = (__u32)ctx->pid;
        emit_and_kill(pid, tgid, BREACH_PTRACE_ATTACH, target);
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Probe 2: mprotect(PROT_WRITE | PROT_EXEC) detection
 *
 * Fires on every mprotect(2) syscall entry. W^X policy: any attempt to mark
 * a memory region both writable and executable from a sandboxed process is
 * a strong indicator of JIT injection or shellcode staging.
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint__syscalls__sys_enter_mprotect(struct mprotect_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)(pid_tgid & 0xFFFFFFFF);

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (!flag || *flag == 0)
        return 0;

    /* Detect PROT_WRITE | PROT_EXEC combination */
    if ((ctx->prot & PROT_WRITE) && (ctx->prot & PROT_EXEC)) {
        emit_and_kill(pid, tgid, BREACH_MPROTECT_WX, 0);
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Probe 3: execve("/bin/sh" | "/bin/bash") detection
 *
 * Fires on every execve(2) syscall entry. If a sandboxed PID attempts to
 * spawn an interactive shell, it is killed immediately. We perform a
 * prefix comparison on the filename argument (read from user space).
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct execve_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)(pid_tgid & 0xFFFFFFFF);

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (!flag || *flag == 0)
        return 0;

    /* Read the filename from user space into a kernel buffer */
    char filename[32] = {0};
    long ret = bpf_probe_read_user_str(filename, sizeof(filename), ctx->filename);
    if (ret <= 0)
        return 0;

    /* Check for /bin/sh */
    if (filename[0] == '/' &&
        filename[1] == 'b' &&
        filename[2] == 'i' &&
        filename[3] == 'n' &&
        filename[4] == '/' &&
        filename[5] == 's' &&
        filename[6] == 'h' &&
        (filename[7] == '\0' || filename[7] == ' ')) {
        emit_and_kill(pid, tgid, BREACH_SHELL_SPAWN, 0);
        return 0;
    }

    /* Check for /bin/bash */
    if (filename[0] == '/' &&
        filename[1] == 'b' &&
        filename[2] == 'i' &&
        filename[3] == 'n' &&
        filename[4] == '/' &&
        filename[5] == 'b' &&
        filename[6] == 'a' &&
        filename[7] == 's' &&
        filename[8] == 'h' &&
        (filename[9] == '\0' || filename[9] == ' ')) {
        emit_and_kill(pid, tgid, BREACH_SHELL_SPAWN, 0);
        return 0;
    }

    /* Check for /usr/bin/bash */
    if (filename[0] == '/' &&
        filename[1] == 'u' &&
        filename[2] == 's' &&
        filename[3] == 'r' &&
        filename[4] == '/' &&
        filename[5] == 'b' &&
        filename[6] == 'i' &&
        filename[7] == 'n' &&
        filename[8] == '/' &&
        filename[9] == 'b' &&
        filename[10] == 'a' &&
        filename[11] == 's' &&
        filename[12] == 'h') {
        emit_and_kill(pid, tgid, BREACH_SHELL_SPAWN, 0);
        return 0;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
