#!/bin/sh

# Create the vmlinux header with all the eBPF Linux functions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -target bpf -g -O2 -c scx_kun.bpf.c -o scx_kun.bpf.o -I.

bpftool gen skeleton scx_kun.bpf.o > scx_kun.bpf.skel.h

gcc -g -O2 -Wall scx_kun.c -o scx_kun -I/usr/include -lbpf -lelf -I.