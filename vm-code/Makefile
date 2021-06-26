INCLUDE_DEPS = $(wildcard $(COMMON_HEADERS)/*.h) $(wildcard ./*.h)

vm-program: vm-program.o util.o linker.ld
	ld -m elf_x86_64 --oformat=binary -T linker.ld vm-program.o -o vm-program -nostdlib

vm-program.o: vm-program.cpp util.h $(INCLUDE_DEPS)
	g++ vm-program.cpp -g -O3 -I$(COMMON_HEADERS) -fno-pie -D_FORTIFY_SOURCE=0 -m64 -ffunction-sections -c -nostdlib -std=c++17 -o vm-program.o
