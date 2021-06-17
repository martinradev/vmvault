#!/bin/sh

# Build C program
gcc vm-program.c -O3 -fno-pie -m64 -c -nostdlib -o vm-program.o

# Or build the one written in assembly
#nasm -felf64 vm-program.nasm -o vm-program.o

ld -m elf_x86_64 --oformat=binary -T linker.ld  vm-program.o -o vm-program -nostdlib

