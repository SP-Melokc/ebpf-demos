// eBPF 程序：追踪 tracepoint/syscalls/sys_enter_execve
// 每次有进程执行新命令(execve)时，把 pid/comm/文件名 推到 ringbuf
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
	int pid;
	char comm[16];
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// sys_enter_* 追踪点的原始上下文布局（等价于内核 struct trace_event_raw_sys_enter）
struct trace_event_raw_sys_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;
	unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// execve 的第一个参数就是 filename，args[0] 指向用户态字符串
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const void *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
