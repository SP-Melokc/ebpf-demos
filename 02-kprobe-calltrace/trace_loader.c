// 用户态加载器：加载 trace_bpf.o，挂到命令行指定的内核函数，消费 ringbuf，
// 用 /proc/kallsyms 把内核栈 IP 符号化成 函数名+偏移。
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_STACK 32

/* 必须与 trace_bpf.c 里的定义完全一致（字段顺序/类型/大小） */
struct stack_event {
	char comm[16];
	__u32 pid;
	__s32 size;
	__u64 ips[MAX_STACK];
};
_Static_assert(sizeof(struct stack_event) == 280, "stack_event size mismatch vs BPF side");

/* ---------- kallsyms 符号化：一次性读入 + 排序后二分 ---------- */
/* 注意：名字最长可到 80+ 字符，必须逐行 fgets 读，不能用 fscanf("%63s")
 * —— 后者会把超长名字截断，残余字符破坏下一行的解析，导致符号表被提前截断。 */
#define KSYM_NAME_MAX 96
#define KSYM_MAX_OFFSET  0x100000UL   /* 偏移超过 1MB 视为不可信（JIT/空洞） */

struct ksym { unsigned long addr; char type; char name[KSYM_NAME_MAX]; };
static struct ksym *ksyms;
static size_t ksym_cnt;

static int ksym_cmp(const void *a, const void *b)
{
	unsigned long x = ((const struct ksym *)a)->addr;
	unsigned long y = ((const struct ksym *)b)->addr;
	return (x > y) - (x < y);
}

static void load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512];

	if (!f) {
		perror("open /proc/kallsyms");
		return;
	}

	size_t cap = 1 << 16;
	ksyms = malloc(cap * sizeof(*ksyms));
	if (!ksyms) { fclose(f); return; }

	while (fgets(line, sizeof(line), f)) {
		unsigned long addr;
		char type, name[KSYM_NAME_MAX];

		/* 格式: <addr> <type> <name> [<module>]；只取前 3 列，剩余整行被丢弃 */
		if (sscanf(line, "%lx %c %95s", &addr, &type, name) != 3)
			continue;
		if (addr == 0)                       /* kptr_restrict 下地址全是 0 */
			continue;
		/* 只保留文本符号(t/T/w/W)，数据符号会污染“就近查找” */
		if (type != 't' && type != 'T' && type != 'w' && type != 'W')
			continue;
		if (ksym_cnt == cap) {
			cap *= 2;
			ksyms = realloc(ksyms, cap * sizeof(*ksyms));
			if (!ksyms) { fclose(f); return; }
		}
		ksyms[ksym_cnt].addr = addr;
		ksyms[ksym_cnt].type = type;
		snprintf(ksyms[ksym_cnt].name, KSYM_NAME_MAX, "%s", name);
		ksym_cnt++;
	}
	fclose(f);

	qsort(ksyms, ksym_cnt, sizeof(*ksyms), ksym_cmp);
	printf("kallsyms: %zu text symbols loaded\n", ksym_cnt);
}

/* 找 <= ip 的最大符号地址；名字/类型写回，返回符号基址（0=没找到） */
static unsigned long resolve(unsigned long ip, char *out, size_t n, char *type)
{
	size_t lo = 0, hi = ksym_cnt, best = 0;

	if (ksym_cnt == 0) {
		snprintf(out, n, "?");
		return 0;
	}
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (ksyms[mid].addr <= ip) { best = mid; lo = mid + 1; }
		else hi = mid;
	}
	if (ksyms[best].addr > ip) {     /* ip 比所有符号都小 */
		snprintf(out, n, "?");
		return 0;
	}
	snprintf(out, n, "%s", ksyms[best].name);
	*type = ksyms[best].type;
	return ksyms[best].addr;
}

/* ---------- ringbuf 回调 ---------- */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct stack_event *e = data;
	int frames = e->size / sizeof(__u64);

	printf("=== pid=%u comm=%s  %d frames ===\n", e->pid, e->comm, frames);
	for (int i = 0; i < frames; i++) {
		char name[KSYM_NAME_MAX], type = '?';
		unsigned long base = resolve(e->ips[i], name, sizeof(name), &type);
		unsigned long off = base ? (unsigned long)(e->ips[i] - base) : 0;

		if (base && off < KSYM_MAX_OFFSET)
			printf("  [%02d] 0x%016llx  %c %s+0x%lx\n", i,
			       (unsigned long long)e->ips[i], type, name, off);
		else            /* 落在 kallsyms 空白区(如 BPF JIT/execmem)，不编假名 */
			printf("  [%02d] 0x%016llx  [unknown]\n", i,
			       (unsigned long long)e->ips[i]);
	}
	return 0;
}

static volatile sig_atomic_t exiting;
static void sig_handler(int s) { exiting = 1; }

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-r] <kernel_function>\n", prog);
	fprintf(stderr, "  -r   用 kretprobe 挂在函数返回处（默认 kprobe 挂入口）\n");
	fprintf(stderr, "  e.g. %s io_schedule\n", prog);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	struct ring_buffer *rb = NULL;
	const char *func;
	bool retprobe = false;
	int err = 0, opt;

	while ((opt = getopt(argc, argv, "rh")) != -1) {
		switch (opt) {
		case 'r': retprobe = true; break;
		default:  usage(argv[0]); return 1;
		}
	}
	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}
	func = argv[optind];

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	load_kallsyms();

	obj = bpf_object__open_file("trace_bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
		fprintf(stderr, "open trace_bpf.o failed: %d\n", err);
		goto out;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_stack");
	if (!prog) {
		fprintf(stderr, "find program failed\n");
		goto out;
	}

	/* 目标函数来自命令行；SEC("kprobe") 只用来推断程序类型 */
	link = bpf_program__attach_kprobe(prog, retprobe, func);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "attach %s%s failed: %d\n",
			retprobe ? "kretprobe " : "kprobe ", func, err);
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

	printf("Tracing %s%s ... Ctrl-C to stop.\n", retprobe ? "kretprobe " : "", func);
	while (!exiting)
		ring_buffer__poll(rb, 100);

out:
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	free(ksyms);
	return err < 0 ? 1 : 0;
}
