#!/bin/sh

# Create the vmlinux header with all the eBPF Linux functions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -target bpf -g -O2 -c scx_nest.bpf.c -o scx_nest.bpf.o -I.

bpftool gen skeleton scx_nest.bpf.o > scx_nest.bpf.skel.h

gcc -g -O2 -Wall scx_nest.c -o scx_nest -I/usr/include -lbpf -lelf -I.