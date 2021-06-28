INCLUDE_DEPS=$(wildcard $(COMMON_HEADERS)/*.h) $(wildcard ./*.h)
CFLAGS=-fno-builtin -g -O3 -fno-pie -D_FORTIFY_SOURCE=0 -m64 -ffunction-sections -nostdlib -std=c++17 -maes

vm-program: vm-program.o tiny-aes.o linker.ld
	ld -m elf_x86_64 --oformat=binary -T linker.ld vm-program.o tiny-aes.o -o vm-program -nostdlib

vm-program.o: vm-program.cpp util.h $(INCLUDE_DEPS)
	g++ vm-program.cpp -I$(COMMON_HEADERS) $(CFLAGS) -c -o vm-program.o

tiny-aes.o: tiny-aes/tiny-aes.h tiny-aes/tiny-aes.c
	gcc tiny-aes/tiny-aes.c $(CFLAGS) -c -o tiny-aes.o
