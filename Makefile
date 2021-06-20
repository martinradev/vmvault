
obj-m += mini-svm.o
mini-svm-objs := \
	src/mini-svm-asm.o \
	src/mini-svm-main.o \
	src/mini-svm-mm.o \
	src/mini-svm-debug.o \
	src/mini-svm-user.o \

#kernel_dir = /home/sisu/code/linux-kernels/linux-5.11.15/
kernel_dir = /usr/lib/modules/5.13.0-rc4+/build

all:
	make -C $(kernel_dir) M=$(PWD) modules
	cp src/mini-svm-user-ioctl.h uapi/.
	cp src/mini-svm-vmcb.h uapi/.
	cp src/mini-svm-exit-codes.h uapi/.
	cp src/mini-svm-common-structures.h uapi/.
	cp hv-user-space/hv-microbench-structures.h uapi/.

	COMMON_HEADERS=$(PWD)/uapi/ make -C hv-user-space
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code

clean:
	make -C $(kernel_dir) M=$(PWD) clean
