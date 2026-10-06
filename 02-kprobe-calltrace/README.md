# 02 · kprobe 内核栈回溯（calltrace）

挂一个 kprobe 到**任意内核函数**上，每当它被调用就抓一份**内核栈**，经 ringbuf 回传给用户态，用 `/proc/kallsyms` 符号化成 `函数名+偏移`。

属于 [eBPF 实战 demo 集](../) 的第 2 个。

## 文件

| 文件 | 作用 |
|---|---|
| `trace_bpf.c` | BPF 程序：`SEC("kprobe")` + `bpf_get_stack()` + ringbuf |
| `trace_loader.c` | 加载器：libbpf 加载/挂载 + kallsyms 符号化 |
| `Makefile` | 用 buildroot 工具链 + sysroot 交叉编译 |

## 前置

**目标内核**需开：

```
CONFIG_KPROBES=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y          # 用 BPF 挂 kprobe
CONFIG_BPF_JIT=y
```

> 本 demo **不需要 BTF**：`bpf_get_stack()` 的第一个参数是 `ARG_PTR_TO_CTX`（不是 BTF ID），普通 kprobe 就能用。所以没开 `CONFIG_DEBUG_INFO_BTF` 的内核照样能跑。

**交叉编译**用目标板同款 buildroot 工具链 + sysroot（`Makefile` 里 `BR_HOST` 指向它）：

```
$BR_HOST/bin/aarch64-buildroot-linux-gnu-gcc
$BR_HOST/aarch64-buildroot-linux-gnu/sysroot   # 内含 libbpf.a / libelf.a / libz.a 和 bpf/ 头文件
```

## 构建

```bash
make                 # 产出 trace_bpf.o（BPF 字节码）+ trace_loader（aarch64 静态可执行）
```

换 SDK 路径：`make BR_HOST=/path/to/buildroot/output/alientek_rk3568/host`

## 运行

把 `trace_loader` 和 `trace_bpf.o` 放**同一目录**（loader 按相对路径打开 `.o`），在板子上：

```bash
echo 0 > /proc/sys/kernel/kptr_restrict    # 否则 kallsyms 地址全是 0，符号化不出来
./trace_loader io_schedule                 # kprobe 挂函数入口
./trace_loader vfs_read                    # 换任意内核函数
./trace_loader -r vfs_read                 # -r 走 kretprobe（挂函数返回处）
```

**目标函数在运行时由命令行指定**，不用重编。想换函数就换个参数（和 bpftrace 的做法一致）。

实测输出（抓 `io_schedule`，jbd2 提交事务时阻塞在 IO）：

```
=== pid=187 comm=jbd2/mmcblk0p6-  8 frames ===
  [00] 0xffffffc0094eb040  T io_schedule+0x0
  [01] 0xffffffc0094eba74  T __wait_on_bit+0x74
  [02] 0xffffffc0094ebb54  T out_of_line_wait_on_bit+0x84
  [03] 0xffffffc0082ea260  T __wait_on_buffer+0x40
  [04] 0xffffffc0083bb208  T jbd2_journal_commit_transaction+0x17b8
  [05] 0xffffffc0083c4a28  t kjournald2+0xe8
  [06] 0xffffffc00807998c  t kthread+0xdc
  [07] 0xffffffc008016610  T ret_from_fork+0x10
```

（`T`=全局函数、`t`=静态函数。）

## 几个关键点

- **`bpf_get_stack(ctx, buf, size, flags)` 返回的是字节数，不是帧数**（帧数 = size / 8）。上限 127 帧。
- **`bpf_ringbuf_reserve()` 之后必须判空**——ringbuf 满时返回 NULL，不判直接解引用会被 verifier 拒绝加载。
- **`bpf_get_stack` 是 GPL-only helper**，license 必须是 `"GPL"`。
- **符号化坑**：解析 `/proc/kallsyms` 必须**逐行 `fgets` + `sscanf`**。符号名最长可达 80+ 字符，用 `fscanf("%63s")` 会被截断、残留字符破坏下一行解析，导致**符号表被提前截断**（实测只读到 11%），高地址函数全部套错名——表现是"被探的函数自己不见了、还多出偏移离谱的假帧"。
- 落在 kallsyms 空白区（如 BPF JIT / 空洞）的帧打印 `[unknown]`，不编假名。
