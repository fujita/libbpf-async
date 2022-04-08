#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_FRAMES 32

struct __attribute__((__packed__)) Stack {
	u64 ip[MAX_FRAMES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} hmap SEC(".maps");

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 4096);
} rb SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	int ret;
	struct Stack *stack;

	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 *val;

	val = bpf_map_lookup_elem(&hmap, &tgid);
	if (!val) {
		return 0;
	}

	stack = bpf_ringbuf_reserve(&rb, sizeof(*stack), 0);
	if (!stack) {
		return 0;
	}

	ret = bpf_get_stack(ctx, (void *)stack->ip, 8 * MAX_FRAMES,
			    BPF_F_USER_STACK);
	if (ret <= 0) {
		bpf_ringbuf_discard(stack, 0);
		return 0;
	}
	bpf_ringbuf_submit(stack, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
