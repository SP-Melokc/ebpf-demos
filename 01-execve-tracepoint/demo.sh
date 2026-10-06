#!/bin/sh
# eBPF execve 追踪 demo 的自运行脚本（作为 rdinit 使用）
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null

# 挂 tracefs（libbpf 从这里读 tracepoint id）
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null

echo "===== eBPF execve trace demo ====="
cd /demo || { echo "!! no /demo"; poweroff -f; exit 1; }

./execve_loader &
PID=$!
sleep 1

echo "--- triggering execve ---"
ls -la / >/dev/null 2>&1
echo "hello eBPF" >/dev/null 2>&1
cat /etc/inittab >/dev/null 2>&1
sh -c "echo nested shell" >/dev/null 2>&1
sleep 2

kill $PID 2>/dev/null
sleep 1
echo "===== demo done, poweroff ====="
poweroff -f
