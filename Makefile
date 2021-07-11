obj-m += mini-svm.o
mini-svm-objs := \
	src/mini-svm-asm.o \
	src/mini-svm-main.o \
	src/mini-svm-mm.o \
	src/mini-svm-debug.o \
	src/mini-svm-user.o \
	src/mini-svm-crypto.o \

all: kernel-module test-env

vm-code: .FORCE $(wildcard vm-code/*)
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code

kernel-module: kernel-module vm-code
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp src/mini-svm-user-ioctl.h uapi/.

test-env:
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean

.FORCE:
