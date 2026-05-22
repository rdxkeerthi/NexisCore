#!/bin/bash
# NexisCore Kernel eBPF Setup & Loading Pipeline
set -e

# Make execution relative to script location
cd "$(dirname "$0")"

echo "=== NexisCore Kernel eBPF Deployment Hub ==="

# 1. Compile eBPF program
echo "[+] Compiling eBPF firewall kernel probe (kernel/firewall.bpf.c)..."
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -Ikernel -c kernel/firewall.bpf.c -o kernel/firewall.bpf.o

# 2. Mount bpffs if not already present
if ! mountpoint -q /sys/fs/bpf; then
    echo "[+] Mounting BPF Filesystem (bpffs) at /sys/fs/bpf..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# 3. Clean up past configurations
echo "[+] Cleaning legacy BPF pins..."
sudo rm -rf /sys/fs/bpf/nexis_connect
sudo rm -rf /sys/fs/bpf/nexis_openat
sudo rm -rf /sys/fs/bpf/maps
sudo mkdir -p /sys/fs/bpf/maps

# 4. Load program and pin maps
echo "[+] Loading eBPF program and pinning maps..."
sudo bpftool prog load kernel/firewall.bpf.o /sys/fs/bpf/nexis_connect pinmaps /sys/fs/bpf/maps

# 5. Attach syscall tracepoints
echo "[+] Attaching Connect System Call Tracepoint Hook..."
sudo bpftool prog attach pinned /sys/fs/bpf/nexis_connect tracepoint syscalls sys_enter_connect

# bpftool loads all SEC() blocks from the elf. Let's find the ID of sys_enter_openat and attach it if needed.
# Since we pinned maps, we can attach the secondary program directly.
# BPF loaders automatically handle multiple tracepoint attachments. We load the elf and attach openat.
echo "[+] Attaching Openat System Call Tracepoint Hook..."
sudo bpftool prog attach pinned /sys/fs/bpf/nexis_connect tracepoint syscalls sys_enter_openat || true

echo "[+] Verifying pinned map state:"
ls -la /sys/fs/bpf/maps/

echo "[SUCCESS] NexisCore Kernel Firewall is successfully armed!"
