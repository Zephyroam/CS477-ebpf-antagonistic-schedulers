#!/bin/sh

# Create the vmlinux header with all the eBPF Linux functions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile the scheduler
clang -target bpf -g -O2 -c scx_minimal.bpf.c -o scx_minimal.bpf.o -I.
clang -target bpf -g -O2 -c scx_central.bpf.c -o scx_central.bpf.o -I.
clang -target bpf -g -O2 -c scx_simple.bpf.c -o scx_simple.bpf.o -I.
