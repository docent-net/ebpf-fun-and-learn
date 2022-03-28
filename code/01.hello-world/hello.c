#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

// set kernel event, on which this program will be triggered
SEC("tracepoint/syscalls/sys_enter_execve")

int bpf_prog(void *ctx) {
    char msg[] = "Hello, BPF world!";

    // print msg int the kernel trace log
    // see sys/kernel/debug/tracing/trace_pipe
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

// required; provide a license of this program; kernel will only
// load GPL code
char _license[] SEC("license") = "GPL";