bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c cache_misses.bpf.c -o cache_misses.bpf.o -I.
bpftool gen skeleton cache_misses.bpf.o > cache_misses.bpf.skel.h
gcc -o cache_misses main.c -lbpf -I.

clang -O2 -g -target bpf -c scx_simple.bpf.c -o scx_simple.bpf.o -I.
bpftool gen skeleton scx_simple.bpf.o > scx_simple.bpf.skel.h
gcc -o scx_simple scx_simple.c -lbpf -I. -I..
