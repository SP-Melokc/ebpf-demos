# eBPF 实战 demo 集

在 **aarch64（RK3568 真机 + QEMU 客户机）** 上从零跑通的 eBPF 小程序。每个 demo 一个目录、一个 README，讲清楚**它干什么、怎么编、怎么跑、踩过什么坑**。

> 配套内核笔记（`ebpf框架` / `ebpf-qemu适配流程` / `ebpf应用场景与实战案例` / `ebpf-kprobe栈回溯demo`）放在本地 Obsidian 笔记库。

## 目录

| Demo | 干什么 | 挂载方式 | 运行环境 |
|---|---|---|---|
| [`01-execve-tracepoint`](01-execve-tracepoint/) | 追踪 `execve`——谁执行了什么命令；ringbuf 回传 `pid / 进程名 / 文件名` | tracepoint | QEMU aarch64 |
| [`02-kprobe-calltrace`](02-kprobe-calltrace/) | 挂**任意**内核函数抓**内核栈**，用户态符号化成 `函数名+偏移` | kprobe / kretprobe | RK3568 真机（buildroot） |

## 共同结构

两个 demo 都是**一个 BPF 程序（内核态）+ 一个 loader（用户态）**：

```
demo/
├── xxx.bpf.c        ← BPF 程序：clang -target bpf 编成字节码，跑在内核(无 main，被动触发)
├── xxx_loader.c     ← 用户态主程序：libbpf 负责 load → attach → 消费 ringbuf
└── Makefile
```

- 两者唯一的约定是 **SEC 名 / 程序名 / map 名 / 结构体布局**——名字对不上就找不到。
- 数据通道都是 **ringbuf**（内核态往里写事件，用户态轮询读出来）。

## 工具链

| 环节 | 用什么 |
|---|---|
| BPF 字节码 | 宿主 `clang`（`-target bpf`，架构无关，同一份 `.o` 可跨架构） |
| 用户态 loader | 交叉 gcc + `libbpf.a` / `libelf.a` / `libz.a`，**静态链接** |
| QEMU demo | Ubuntu 交叉工具链 `aarch64-linux-gnu-gcc` + 手抽 arm64 静态库（见 `01-execve-tracepoint/README.md`） |
| RK3568 demo | buildroot 自带工具链 + sysroot（见 `02-kprobe-calltrace/Makefile`） |

## 许可

GPL-2.0。BPF 程序里用了 GPL-only helper（如 `bpf_get_stack`），`char LICENSE[] SEC("license") = "GPL"` 不能省。
