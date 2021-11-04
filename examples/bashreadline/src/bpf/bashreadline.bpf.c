#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 256

struct __attribute__ ((__packed__)) str_t {
    u64 pid;
    char str[120];
};

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256*1024);
} rb SEC(".maps");

SEC("uretprobe/triger_func")
int printret(struct pt_regs *ctx) {
    bpf_printk("printret entered");
    struct str_t data  = {};
    char comm[TASK_COMM_LEN] = {};
    u32 pid;
    if (!PT_REGS_RC(ctx))
        return 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
        bpf_ringbuf_output(&rb, &data, sizeof(data), 0);
    }

    return 0;
};

char _license[] SEC("license") = "GPL";
