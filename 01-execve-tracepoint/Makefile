# eBPF execve 追踪 demo —— 独立构建（不接入 buildroot 包体系）
# 前置见 README.md；改好 KERNEL_DIR / CLANG / CROSS 后直接 make
CLANG       ?= clang
CROSS       ?= aarch64-linux-gnu-
KERNEL_DIR  ?= $(HOME)/QEMU/qemu_linux
LIBBPF_DIR  := $(KERNEL_DIR)/tools/lib/bpf
LIBBPF_A    := $(LIBBPF_DIR)/libbpf.a

# aarch64 静态库目录（获取方式见 README「arm64 静态库」）
ARM64_LIB   ?= /tmp/arm64x/usr/lib/aarch64-linux-gnu

# 内核 uapi 头文件 + libbpf 头（注意 -I tools/lib 而非 tools/lib/bpf）
UAPI_INC := -I$(KERNEL_DIR)/tools/lib \
            -I$(KERNEL_DIR)/tools/include/uapi \
            -I$(KERNEL_DIR)/include/uapi \
            -I$(KERNEL_DIR)/arch/arm64/include/uapi \
            -I$(KERNEL_DIR)/arch/arm64/include \
            -I$(KERNEL_DIR)/tools/include

all: execve_trace.bpf.o execve_loader

execve_trace.bpf.o: execve_trace.bpf.c
	$(CLANG) -target bpf -g -O2 -D__TARGET_ARCH_arm64 $(UAPI_INC) -c $< -o $@

execve_loader: execve_loader.c $(LIBBPF_A)
	$(CROSS)gcc -static -O2 $(UAPI_INC) -o $@ $< $(LIBBPF_A) \
	    $(ARM64_LIB)/libelf.a $(ARM64_LIB)/libz.a -lpthread

clean:
	rm -f execve_trace.bpf.o execve_loader
