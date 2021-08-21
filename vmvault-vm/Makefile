INCLUDE_DEPS=$(wildcard $(COMMON_HEADERS)/*.h) $(wildcard ./*.h)
CFLAGS=-fno-builtin -g -Os -fno-pie -D_FORTIFY_SOURCE=0 -m64 -ffunction-sections -nostdlib -std=c++17 -maes -mavx2 -fno-exceptions -fno-rtti

vm-program: vm-program.o linker.ld
	ld -m elf_x86_64 --oformat=binary -T linker.ld vm-program.o -o vm-program -nostdlib
	xxd -i ./vm-program ../vmvault-hv/vm-program.h

vm-program.o: vm-program.cpp util.h $(INCLUDE_DEPS)
	g++ vm-program.cpp -I$(COMMON_HEADERS) $(CFLAGS) -c -o vm-program.o
