#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>

#include "mini-svm-user-ioctl.h"
#include "mini-svm-vmcb.h"

static void dump_regs(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	printf("rip = %lx\n", state->regs.rip);
	printf("rcx = %lx\n", state->regs.rcx);
	printf("rbx = %lx\n", state->regs.rbx);
	printf("rax = %lx\n", state->regs.rax);
	printf("is_dead = %d\n", state->is_dead);
}

int main() {
	int fd = open("/dev/mini_svm", O_RDWR);
	if (fd < 0) {
		printf("Failed to open mini-svm\n");
		return -1;
	}
	void *pages = mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pages == MAP_FAILED) {
		printf("Failed to mmap regions\n");
		return -1;
	}

	struct mini_svm_vmcb *vmcb = (struct mini_svm_vmcb *)pages;
	struct mini_svm_vm_state *state = (struct mini_svm_vm_state *)((unsigned long)pages + 0x1000UL);

	int r = ioctl(fd, MINI_SVM_IOCTL_START, 0);
	if (r < 0) {
		printf("Failed to ioctl mini-svm\n");
		return -1;
	}
	dump_regs(vmcb, state);

	while(!state->is_dead) {
		int r = ioctl(fd, MINI_SVM_IOCTL_RESUME, 0);
		if (r < 0) {
			printf("Failed to ioctl mini-svm\n");
			return -1;
		}
		dump_regs(vmcb, state);
	}

	return 0;
}
