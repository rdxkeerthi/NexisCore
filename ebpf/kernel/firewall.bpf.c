#include <linux/bpf.h>
#include <linux/types.h>
#include "bpf_helpers.h"

#define AF_INET 2

/* Packed log event structure for high-throughput Ring Buffer */
typedef struct {
    __u32 pid;
    __u32 breach_type; /* 1 = Egress Tampering, 2 = File Boundary Abuse */
    char comm[16];
} __attribute__((packed)) log_event_t;

/* BPF LPM Trie Key structure for DNS domain whitelist matching */
struct dns_whitelist_key {
    __u32 prefixlen;
    char name[64];
};

/* BPF Hash Map mapping container process PIDs to active lock state flag */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} locked_sandboxes SEC(".maps");

/* BPF Hash Map mapping dynamically whitelisted IPv4 addresses for TCP connections */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

/* BPF Ring Buffer Map to stream audit logs to user space with 16MB capacity allocation */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16MB capacity */
} security_events_ring SEC(".maps");

/* BPF LPM Radix Trie map containing whitelisted corporate API endpoints */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(struct bpf_lpm_trie_key) + 64);
    __uint(value_size, sizeof(__u32));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dns_whitelist SEC(".maps");

/* Custom structures for raw network packet parsing to avoid system header collisions */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
} __attribute__((packed));

struct iphdr {
    unsigned char ihl:4, version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
} __attribute__((packed));

struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
} __attribute__((packed));

struct in_addr {
    unsigned int s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

struct sys_enter_connect_args {
    unsigned long long unused;
    int fd;
    const struct sockaddr *uservaddr;
    int addrlen;
};

struct openat_args {
    unsigned long long unused;
    int dfd;
    const char *filename;
    int flags;
    unsigned short mode;
};

/* Portability macro for htons */
#define bpf_htons(x) ((__u16)((((__u16)(x) & 0x00ffU) << 8) | (((__u16)(x) & 0xff00U) >> 8)))

/* Static inline helper to check if a substring exists within a source buffer */
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

/* Static inline helper to check if a string starts with a specific prefix */
static inline int starts_with(const char *str, const char *prefix, int prefix_len) {
    for (int i = 0; i < prefix_len; i++) {
        if (str[i] != prefix[i]) return 0;
    }
    return 1;
}

/* 1. eBPF Socket Filtering Program - Intercept outgoing DNS Queries */
SEC("socket/dns_filter")
int socket__dns_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ETH header parsing */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    /* IPv4 packets only */
    if (eth->h_proto != bpf_htons(0x0800)) return -1;

    /* IP header parsing */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;

    /* UDP packets only */
    if (ip->protocol != 17) return -1;

    /* UDP header parsing */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return -1;

    /* UDP destination port 53 (DNS) queries only */
    if (udp->dest != bpf_htons(53)) return -1;

    /* Assert that process is a locked sandbox PID */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (!flag || *flag == 0) {
        return -1; /* Pass unconstrained process network traffic */
    }

    /* Parse DNS Query domain labels */
    unsigned char *dns = (unsigned char *)(udp + 1);
    if ((void *)(dns + 12) > data_end) return -1;

    /* DNS name starts 12 bytes after UDP header (DNS Header size = 12) */
    unsigned char *name_start = dns + 12;
    char domain[64] = {0};
    int domain_len = 0;

    unsigned char *curr = name_start;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if ((void *)(curr + 1) > data_end) break;
        unsigned char label_len = *curr;
        if (label_len == 0) break;

        curr++; /* Skip length byte to start of label string */

        if (domain_len > 0 && domain_len < 63) {
            domain[domain_len] = '.';
            domain_len++;
        }

        for (int j = 0; j < 63; j++) {
            if (j >= label_len) break;
            if ((void *)(curr + 1) > data_end) break;
            if (domain_len < 63) {
                domain[domain_len] = *curr;
                domain_len++;
            }
            curr++;
        }
    }

    /* Query matching against Radix trie */
    struct dns_whitelist_key key = {0};
    key.prefixlen = 512; /* Exact bitwise match on 64-byte boundary */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        key.name[i] = domain[i];
    }

    void *whitelisted = bpf_map_lookup_elem(&dns_whitelist, &key);
    if (whitelisted) {
        return -1; /* Allow approved domain resolution */
    }

    /* Reject unauthorized DNS exfiltration attempts! */
    log_event_t event = {0};
    event.pid = pid;
    event.breach_type = 1; /* Egress Tampering */
    char default_comm[16] = "mcp_sandbox";
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.comm[i] = default_comm[i];
    }

    bpf_ringbuf_output(&security_events_ring, &event, sizeof(event), 0);
    return 0; /* Drop DNS Packet in filter layer */
}

/* 2. syscall tracepoint - Block connections to raw IPs unless they are whitelisted */
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct sys_enter_connect_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (flag && *flag != 0) {
        struct sockaddr_in sin = {0};
        long bytes_read = bpf_probe_read_user(&sin, sizeof(sin), ctx->uservaddr);
        if (bytes_read == 0 && sin.sin_family == AF_INET) {
            __u32 ip = sin.sin_addr.s_addr;

            /* Allow localhost connections (127.0.0.1 = 0x0100007f in network byte order) */
            if (ip == 0x0100007f) {
                return 0;
            }

            /* Lookup destination in dynamically validated allowed_ips map */
            __u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &ip);
            if (allowed && *allowed != 0) {
                return 0;
            }

            /* Block unauthorized direct connection and terminate thread */
            log_event_t event = {0};
            event.pid = pid;
            event.breach_type = 1; /* Egress Tampering */
            char default_comm[16] = "mcp_sandbox";
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                event.comm[i] = default_comm[i];
            }

            bpf_ringbuf_output(&security_events_ring, &event, sizeof(event), 0);
            bpf_send_signal(SIGKILL);
        }
    }
    return 0;
}

/* 3. Openat tracepoint - Block accesses outside of allowed prefix locations */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct openat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *flag = bpf_map_lookup_elem(&locked_sandboxes, &pid);
    if (flag && *flag != 0) {
        char path_buf[64] = {0};
        long bytes_read = bpf_probe_read_user_str(path_buf, sizeof(path_buf), ctx->filename);
        if (bytes_read > 0) {
            int breach = 0;

            /* Search for restricted system files or directory structures */
            if (contains_substring(path_buf, "/etc/", 64, 5)) breach = 1;
            else if (contains_substring(path_buf, "../", 64, 3)) breach = 1;
            else if (contains_substring(path_buf, "private_key.pem", 64, 15)) breach = 1;
            else if (contains_substring(path_buf, "public_key.pem", 64, 14)) breach = 1;
            
            /* Enforce strict prefix constraints for sandboxed operations (only allow /app/ or /tmp/) */
            else if (path_buf[0] == '/' && !starts_with(path_buf, "/app/", 5) && !starts_with(path_buf, "/tmp/", 5) && !starts_with(path_buf, "/dev/null", 9)) {
                breach = 1;
            }

            if (breach != 0) {
                log_event_t event = {0};
                event.pid = pid;
                event.breach_type = 2; /* File Boundary Abuse */
                char default_comm[16] = "mcp_sandbox";
                #pragma unroll
                for (int i = 0; i < 16; i++) {
                    event.comm[i] = default_comm[i];
                }

                bpf_ringbuf_output(&security_events_ring, &event, sizeof(event), 0);
                bpf_send_signal(SIGKILL);
            }
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
