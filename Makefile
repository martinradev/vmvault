
obj-m += mini-svm.o
mini-svm-objs := \
	src/mini-svm-asm.o \
	src/mini-svm-main.o \
	src/mini-svm-exit-codes.o \
	src/mini-svm-mm.o \
	src/mini-svm-debug.o

kernel_dir = /home/sisu/code/linux-kernels/linux-5.11.15/
#kernel_dir = /usr/lib/modules/5.13.0-rc4+/build

all:
	make -C $(kernel_dir) M=$(PWD) modules

clean:
	make -C $(kernel_dir) M=$(PWD) clean
