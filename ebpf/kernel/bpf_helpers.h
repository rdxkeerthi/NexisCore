#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF Map Types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF Map Flags */
#define BPF_F_NO_PREALLOC 1

/* Syscall / Signal Codes */
#define SIGKILL 9

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Helper functions map to static kernel helper function pointer indexes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_send_signal)(__u32 sig) = (void *) 109;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static long (*bpf_ringbuf_output)(void *ringbuf, const void *data, __u64 size, __u64 flags) = (void *) 130;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 113;
static long (*bpf_skb_load_bytes)(const void *ctx, __u32 offset, void *to, __u32 len) = (void *) 26;

#endif /* __BPF_HELPERS_H__ */
