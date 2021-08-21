obj-m += vmvault.o
vmvault-objs := \
	vmvault-hv/vmvault-asm.o \
	vmvault-hv/vmvault-main.o \
	vmvault-hv/vmvault-mm.o \
	vmvault-hv/vmvault-debug.o \
	vmvault-hv/vmvault-user.o \
	vmvault-hv/vmvault-crypto.o \

all: kernel-module test-env

vmvault-vm: .FORCE
	COMMON_HEADERS=$(PWD)/uapi/ make -C vmvault-vm

kernel-module: kernel-module vmvault-vm
	make -C $(KERNEL_DIR) M=$(PWD) modules
	cp vmvault-hv/vmvault-user-ioctl.h uapi/.

test-env:
	make -C testing

clean:
	make -C $(kernel_dir) M=$(PWD) clean

.FORCE:
