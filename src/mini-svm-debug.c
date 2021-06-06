#ifndef MINI_SVM_DEBUG_H
#define MINI_SVM_DEBUG_H

#include "mini-svm-vmcb.h"
#include "mini-svm-debug.h"

#include <linux/kernel.h>

void mini_svm_dump_vmcb(struct mini_svm_vmcb *vmcb) {
	printk("=============\n");
	printk("Control:\n");
	printk("CR read: %.16llx\n", *(__u64 *)&vmcb->control.cr_rd_intercepts);
	printk("CR write: %.16llx\n", *(__u64 *)&vmcb->control.cr_wr_intercepts);
	printk("exitcode: %.16llx\n", *(__u64 *)&vmcb->control.exitcode);
	printk("exitinfo_v1: %.16llx\n", *(__u64 *)&vmcb->control.exitinfo_v1);
	printk("exitinfo_v2: %.16llx\n", *(__u64 *)&vmcb->control.exitinfo_v2);
	printk("exitintinfo: %.16llx\n", *(__u64 *)&vmcb->control.exitintinfo);
	printk("nRIP: %.16llx\n", *(__u64 *)&vmcb->control.nRIP);
	printk("ncr3: %.16llx\n", *(__u64 *)&vmcb->control.ncr3);
	printk("num bytes fetched: %.16llx\n", *(__u64 *)&vmcb->control.num_bytes_fetched);
	printk("\nSave:\n");
	printk("cr0: %.16llx\n", *(__u64 *)&vmcb->save.cr0);
	printk("cr2: %.16llx\n", *(__u64 *)&vmcb->save.cr2);
	printk("cr3: %.16llx\n", *(__u64 *)&vmcb->save.cr3);
	printk("cr4: %.16llx\n", *(__u64 *)&vmcb->save.cr4);
	printk("rax: %.16llx\n", *(__u64 *)&vmcb->save.rax);
	printk("rip: %.16llx\n", *(__u64 *)&vmcb->save.rip);
	printk("rsp: %.16llx\n", *(__u64 *)&vmcb->save.rsp);
	printk("=============\n");
}

#endif // MINI_SVM_DEBUG_H
