
vm-program: vm-program.o util.o
	ld -m elf_x86_64 --oformat=binary -T linker.ld vm-program.o util.o -o vm-program -nostdlib

vm-program.o: vm-program.c util.h
	echo $COMMON_HEADERS
	g++ vm-program.c -O3 -I$(COMMON_HEADERS) -fno-pie -m64 -c -nostdlib -std=c++17 -o vm-program.o

util.o: util.c util.h
	g++ util.c -O3 -fno-pie -I$(COMMON_HEADERS) -m64 -c -nostdlib -std=c++17 -o util.o

# Or build the one written in assembly
#nasm -felf64 vm-program.nasm -o vm-program.o

