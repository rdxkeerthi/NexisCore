#include <linux/bpf.h>
#include <linux/types.h>
#include "bpf_helpers.h"

// Struct definitions matching user-space telemetry schemas
struct security_event_t {
    __u32 process_id;
    __u32 security_violation_type; // 1 = Network Socket Breach, 2 = File Read Bypass
    char comm[16];
};

// BPF Hash Map mapping unsigned 32-bit PID to 32-bit tracking flag
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} locked_sandboxes SEC(".maps");

// BPF Ring Buffer Map to stream audit logs to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB Ring buffer
} security_events_ring SEC(".maps");

// Static inline helper to check if character matches target character
static inline int contains_substring(const char *str, const char *sub, int str_len, int sub_len) {
    if (sub_len > str_len) return 0;
    
    for (int i = 0; i <= str_len - sub_len; i++) {
        int found = 1;
        for (int j = 0; j < sub_len; j++) {
            if (str[i + j] != sub[j]) {
                found = 0;
                break;
            }
        }
        if (found) return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (flag && *flag != 0) {
        // Build Telemetry Packet
        struct security_event_t *event = bpf_ringbuf_reserve(&security_events_ring, sizeof(struct security_event_t), 0);
        if (event) {
            event->process_id = pid;
            event->security_violation_type = 1; // Network Socket Breach
            
            // Read active process name
            __u64 task = 0; // dummy for reading
            // Fallback string if reading gets blocked or skipped
            char default_comm[16] = "mcp_sandbox";
            for (int i = 0; i < 16; i++) {
                event->comm[i] = default_comm[i];
            }
            
            bpf_ringbuf_submit(event, 0);
        }

        char fmt[] = "NexisCore Firewall: Blocked unauthorized connect() attempt from sandboxed PID %d\n";
        bpf_trace_printk(fmt, sizeof(fmt), pid);
        
        bpf_send_signal(9); // SIGKILL
    }

    return 0;
}

// Struct layout for openat syscall parameters
struct openat_args {
    unsigned long long unused;
    int dfd;
    const char *filename;
    int flags;
    unsigned short mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct openat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (flag && *flag != 0) {
        char path_buf[64] = {0};
        
        // Read the target filename path string parameter from user space
        long bytes_read = bpf_probe_read_user_str(path_buf, sizeof(path_buf), ctx->filename);
        if (bytes_read > 0) {
            int breach = 0;

            // Search for restricted system strings: "/etc/", "../", "/certs/"
            if (contains_substring(path_buf, "/etc/", 64, 5)) breach = 1;
            else if (contains_substring(path_buf, "../", 64, 3)) breach = 1;
            else if (contains_substring(path_buf, "/certs/", 64, 7)) breach = 1;

            if (breach != 0) {
                // Build and submit telemetry alert packet
                struct security_event_t *event = bpf_ringbuf_reserve(&security_events_ring, sizeof(struct security_event_t), 0);
                if (event) {
                    event->process_id = pid;
                    event->security_violation_type = 2; // File Read Bypass
                    
                    char default_comm[16] = "mcp_sandbox";
                    for (int i = 0; i < 16; i++) {
                        event->comm[i] = default_comm[i];
                    }
                    
                    bpf_ringbuf_submit(event, 0);
                }

                char fmt[] = "NexisCore Firewall: Blocked unauthorized openat() bypass path: %s from PID %d\n";
                bpf_trace_printk(fmt, sizeof(fmt), path_buf, pid);
                
                bpf_send_signal(9); // SIGKILL
            }
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
