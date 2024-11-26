clang -target bpf -g -O2 -c scx_simple.bpf.c -o scx_simple.bpf.o

bpftool gen skeleton scx_simple.bpf.o > scx_simple.bpf.skel.h

gcc -g -O2 -Wall scx_simple.c -o scx_simple -I/usr/include -lbpf -lelf