#include <linux/bpf.h>
#include <linux/types.h>
#include "bpf_helpers.h"

// BPF Hash Map mapping unsigned 32-bit PID to 32-bit tracking flag
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} locked_sandboxes SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(void *ctx) {
    // 1. Read calling execution thread context using bpf_get_current_pid_tgid()
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // 2. Shift bits right to isolate the true user-space PID (top 32 bits of pid_tgid)
    __u32 pid = pid_tgid >> 32;

    // 3. Look up this extracted PID inside the 'locked_sandboxes' table
    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    
    if (flag) {
        // If lookup returns an active tracking value
        if (*flag != 0) {
            // Print a security log message to the kernel trace buffer
            char fmt[] = "NexisCore Firewall: Blocked unauthorized connect() attempt from sandboxed PID %d\n";
            bpf_trace_printk(fmt, sizeof(fmt), pid);
            
            // Terminate the calling thread instantly by executing bpf_send_signal(9) (SIGKILL)
            bpf_send_signal(9);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
