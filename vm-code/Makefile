
vm-program: vm-program.o util.o linker.ld
	ld -m elf_x86_64 --oformat=binary -T linker.ld vm-program.o util.o -o vm-program -nostdlib

vm-program.o: vm-program.cpp util.h
	g++ vm-program.cpp -g -O3 -I$(COMMON_HEADERS) -fno-pie -m64 -ffunction-sections -c -nostdlib -std=c++17 -o vm-program.o

util.o: util.cpp util.h
	g++ util.cpp -g -O3 -fno-pie -I$(COMMON_HEADERS) -m64 -c -nostdlib -std=c++17 -o util.o

# Or build the one written in assembly
#nasm -felf64 vm-program.nasm -o vm-program.o

