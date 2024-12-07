#!/bin/sh

# Create the vmlinux header with all the eBPF Linux functions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -target bpf -g -O2 -c scx_simple.bpf.c -o scx_simple.bpf.o -I.

bpftool gen skeleton scx_simple.bpf.o > scx_simple.skel.h

gcc -g -O2 -Wall scx_simple.c -o scx_simple -I/usr/include -lbpf -lelf -I.