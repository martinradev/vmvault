#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>

#include "mini-svm-user-ioctl.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-vmcb.h"

#define MINI_SVM_MAX_PHYS_SIZE (32UL * 1024UL * 1024UL)

static void setup_ctrl(struct mini_svm_vmcb_control *ctrl) {
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec3.cpuid_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmmcall_intercept = 1;
	ctrl->vec3.rdtsc_intercept = 1;
	ctrl->vec4.rdtscp_intercept = 1;
}

static void dump_regs(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	printf("rip = %llx\n", state->regs.rip);
	printf("rcx = %llx\n", state->regs.rcx);
	printf("rbx = %llx\n", state->regs.rbx);
	printf("rax = %llx\n", state->regs.rax);
}

static void mini_svm_handle_exception(const enum MINI_SVM_EXCEPTION excp) {
	printf("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_mini_svm_exception_number_to_str(excp));
}

void mini_svm_intercept_rdtsc(struct mini_svm_vm_state *state) {
	state->regs.rax = (state->clock & 0xFFFFFFFFUL);
	state->regs.rdx = ((state->clock >> 32U) & 0xFFFFFFFFUL);
	state->clock++;
}

void mini_svm_intercept_rdtscp(struct mini_svm_vm_state *state) {
	state->regs.rcx = 0x1337UL;
	mini_svm_intercept_rdtsc(state);
}

int mini_svm_intercept_npf(const struct mini_svm_vmcb *vmcb) {
	__u64 fault_phys_address = vmcb->control.exitinfo_v2;
	printf("Received NPF at phys addr: 0x%llx\n", vmcb->control.exitinfo_v2);
	if (fault_phys_address >= MINI_SVM_MAX_PHYS_SIZE) {
		return 1;
	}
	return 1;
}

int mini_svm_intercept_cpuid(struct mini_svm_vm_state *state) {
	return 0;
}

int mini_svm_intercept_vmmcall(struct mini_svm_vm_state *state) {
	return 0;
}

static int mini_svm_handle_exit(const struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	__u64 exitcode = get_exitcode(&vmcb->control);
	int should_exit = 0;

	// TODO: Doing this through function pointers for the respective handlers is probably better.
	printf("exitcode: %llx. Name: %s\n", exitcode, translate_mini_svm_exitcode_to_str(exitcode));
	switch(exitcode) {
		case MINI_SVM_EXITCODE_VMEXIT_EXCP_0 ... MINI_SVM_EXITCODE_VMEXIT_EXCP_15:
			mini_svm_handle_exception((enum MINI_SVM_EXCEPTION)(exitcode - MINI_SVM_EXITCODE_VMEXIT_EXCP_0));
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_RDTSC:
			mini_svm_intercept_rdtsc(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_RDTSCP:
			mini_svm_intercept_rdtscp(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_INVALID:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_HLT:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_NPF:
			should_exit = mini_svm_intercept_npf(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_CPUID:
			should_exit = mini_svm_intercept_cpuid(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_VMMCALL:
			should_exit = mini_svm_intercept_vmmcall(state);
			break;
		default:
			printf("Unkown exit code\n");
			should_exit = 1;
			break;
	}
	return should_exit;
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
	setup_ctrl(&vmcb->control);

	int r = ioctl(fd, MINI_SVM_IOCTL_START, 0);
	if (r < 0) {
		printf("Failed to ioctl mini-svm\n");
		return -1;
	}

	int should_exit;
	do {
		dump_regs(vmcb, state);
		should_exit = mini_svm_handle_exit(vmcb, state);
		if (should_exit) {
			break;
		}
		int r = ioctl(fd, MINI_SVM_IOCTL_RESUME, 0);
		if (r < 0) {
			printf("Failed to ioctl mini-svm\n");
			return -1;
		}
	} while(1);

	return 0;
}
