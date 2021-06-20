# Invoke this script as
#	`KERNEL_DIR=/usr/lib/modules/5.13.0-rc4+/build make`.
#	or wherever the kernel tree is.

obj-m += mini-svm.o
mini-svm-objs := \
	src/mini-svm-asm.o \
	src/mini-svm-main.o \
	src/mini-svm-mm.o \
	src/mini-svm-debug.o \
	src/mini-svm-user.o \

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp src/mini-svm-user-ioctl.h uapi/.
	cp src/mini-svm-vmcb.h uapi/.
	cp src/mini-svm-exit-codes.h uapi/.
	cp src/mini-svm-common-structures.h uapi/.
	cp hv-user-space/hv-microbench-structures.h uapi/.

	COMMON_HEADERS=$(PWD)/uapi/ make -C hv-user-space
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean
