obj-m += sevault-mini.o
sevault-mini-objs := \
	sevault-mini-hv/sevault-mini-asm.o \
	sevault-mini-hv/sevault-mini-main.o \
	sevault-mini-hv/sevault-mini-mm.o \
	sevault-mini-hv/sevault-mini-debug.o \
	sevault-mini-hv/sevault-mini-user.o \
	sevault-mini-hv/sevault-mini-crypto.o \

all: kernel-module test-env

vm-code: .FORCE
	COMMON_HEADERS=$(PWD)/uapi/ make -C vm-code

kernel-module: kernel-module vm-code
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp sevault-mini-hv/sevault-mini-user-ioctl.h uapi/.

test-env:
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean

.FORCE:
