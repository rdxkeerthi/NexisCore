#!/bin/bash
# NexisCore Kernel eBPF Setup & Loading Pipeline
set -e

echo "=== NexisCore Kernel eBPF Deployment Hub ==="

# 1. Compile eBPF program
echo "[+] Compiling eBPF firewall kernel probe (firewall.bpf.c)..."
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -c firewall.bpf.c -o firewall.bpf.o

# 2. Mount bpffs if not already present
if ! mountpoint -q /sys/fs/bpf; then
    echo "[+] Mounting BPF Filesystem (bpffs) at /sys/fs/bpf..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# 3. Clean up past configurations
echo "[+] Cleaning legacy BPF pins..."
sudo rm -rf /sys/fs/bpf/nexiscore_firewall
sudo rm -rf /sys/fs/bpf/nexiscore_maps

# 4. Create maps directory
sudo mkdir -p /sys/fs/bpf/nexiscore_maps

# 5. Load program and pin maps
echo "[+] Loading and attaching eBPF firewall program to connect tracepoint..."
if bpftool prog load help 2>&1 | grep -q "autoattach"; then
    sudo bpftool prog load firewall.bpf.o /sys/fs/bpf/nexiscore_firewall autoattach pinmaps /sys/fs/bpf/nexiscore_maps
else
    # Fallback if autoattach is not supported by this bpftool build (should be supported in modern systems)
    sudo bpftool prog load firewall.bpf.o /sys/fs/bpf/nexiscore_firewall pinmaps /sys/fs/bpf/nexiscore_maps
    sudo bpftool prog attach pinned /sys/fs/bpf/nexiscore_firewall tracepoint syscalls sys_enter_connect
fi

echo "[+] Verifying pinned map state:"
ls -la /sys/fs/bpf/nexiscore_maps/

echo "[SUCCESS] NexisCore Kernel Firewall is successfully armed!"
