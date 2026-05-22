#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#define SEC(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_HASH 1

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Helper functions map to static kernel helper function pointer indexes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_send_signal)(__u32 sig) = (void *) 109;

#endif /* __BPF_HELPERS_H__ */
