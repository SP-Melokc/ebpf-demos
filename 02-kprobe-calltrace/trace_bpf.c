// BPF 程序：在某个内核函数上抓栈（目标函数由 loader 在运行时指定），经 ringbuf 回传用户态
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>        /* ★ 原为 bpf_helper.h，拼错了；应是 bpf_helpers.h */

#define MAX_STACK 32

struct stack_event {
	char comm[16];
	__u32 pid;
	__s32 size;                 /* bpf_get_stack 返回的字节数（帧数 = size / 8） */
	__u64 ips[MAX_STACK];
};

/* ring buffer for kernel & app */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* 不带符号：目标函数由 loader 在运行时通过 bpf_program__attach_kprobe() 指定 */
SEC("kprobe")
int trace_stack(struct pt_regs *ctx)
{
	struct stack_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)                     /* ★ 原缺此检查：ringbuf 满时 reserve 返回 NULL，直接解引用会被 verifier 拒/崩 */
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->size = bpf_get_stack(ctx, e->ips, sizeof(e->ips), 0);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (e->size <= 0) {         /* <0 出错，0 无栈 */
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
