// 用户态加载器：加载 execve_trace.bpf.o，挂到 tracepoint，消费 ringbuf 事件并打印
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

struct event {
	int pid;
	char comm[16];
	char filename[256];
};

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	printf("execve: pid=%-6d comm=%-16s file=%s\n",
	       e->pid, e->comm, e->filename);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	struct ring_buffer *rb = NULL;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = bpf_object__open_file("execve_trace.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "open .o failed\n");
		goto out;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_execve");
	if (!prog) {
		fprintf(stderr, "find program failed\n");
		goto out;
	}

	link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
	if (libbpf_get_error(link)) {
		fprintf(stderr, "attach tracepoint failed\n");
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		fprintf(stderr, "find map failed\n");
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf create failed\n");
		goto out;
	}

	printf("Tracing execve... 另开一个 shell 跑几条命令，或直接 Ctrl-C 结束。\n");

	while (!exiting)
		ring_buffer__poll(rb, 100);

out:
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
