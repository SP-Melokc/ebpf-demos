# RK3568 (aarch64 buildroot) eBPF 栈追踪 demo —— 独立构建
# 用板子同款 buildroot 工具链 + sysroot 静态链接，产物直接丢到 RK3568 跑
#
#   make           # 编 trace_bpf.o + trace_loader
#   make clean
#
# 改了 SDK 路径就覆盖 BR_HOST 即可，例如：
#   make BR_HOST=/path/to/buildroot/output/alientek_rk3568/host

CLANG    ?= clang
BR_HOST  ?= $(HOME)/atk_dlrk3568_linux6.1_sdk/atk_dlrk3568_linux6.1/buildroot/output/alientek_rk3568/host
CROSS    ?= $(BR_HOST)/bin/aarch64-buildroot-linux-gnu-
SYSROOT  ?= $(BR_HOST)/aarch64-buildroot-linux-gnu/sysroot

# BPF 程序编译用的头文件（sysroot 里带 linux/bpf.h 和 bpf/bpf_helpers.h）
BPF_INC  := -I$(SYSROOT)/usr/include

all: trace_bpf.o trace_loader

# BPF 字节码：host 的 clang，-target bpf，架构无关
trace_bpf.o: trace_bpf.c
	$(CLANG) -target bpf -g -O2 -D__TARGET_ARCH_arm64 $(BPF_INC) -c $< -o $@

# 用户态 loader：buildroot 交叉 gcc，静态链接（在 3568 上不依赖任何 .so）
trace_loader: trace_loader.c
	$(CROSS)gcc -static -O2 -I$(SYSROOT)/usr/include -o $@ $< \
	    $(SYSROOT)/usr/lib/libbpf.a \
	    $(SYSROOT)/usr/lib/libelf.a \
	    $(SYSROOT)/usr/lib/libz.a -lpthread

clean:
	rm -f trace_bpf.o trace_loader

.PHONY: all clean
