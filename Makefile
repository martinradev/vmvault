obj-m += sevault-mini.o
sevault-mini-objs := \
	src/sevault-mini-asm.o \
	src/sevault-mini-main.o \
	src/sevault-mini-mm.o \
	src/sevault-mini-debug.o \
	src/sevault-mini-user.o \
	src/sevault-mini-crypto.o \

all: kernel-module test-env

vm-code: .FORCE
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code

kernel-module: kernel-module vm-code
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp src/sevault-mini-user-ioctl.h uapi/.

test-env:
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean

.FORCE:
