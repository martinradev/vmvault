obj-m += mini-svm.o
mini-svm-objs := \
	src/mini-svm-asm.o \
	src/mini-svm-main.o \
	src/mini-svm-mm.o \
	src/mini-svm-debug.o \
	src/mini-svm-user.o \

all: kernel-module vm-code test-env

vm-code:
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code

kernel-module: kernel-module
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp src/mini-svm-user-ioctl.h uapi/.

test-env:
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean
