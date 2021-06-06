#include "mini-svm-mm.h"

#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/io.h>

static const __u64 MINI_SVM_PRESENT_MASK = 0x1UL;
static const __u64 MINI_SVM_WRITEABLE_MASK = 0x2UL;
static const __u64 MINI_SVM_USER_MASK = 0x4UL;
//static const __u64 MINI_SVM_USER_MASK = 0x0UL;

static __u64 mini_svm_create_entry(__u64 pa, __u64 mask) {
	return pa | mask;
}

struct mini_svm_guest_table *mini_svm_construct_debug_mm_one_page(void *vm_page) {
	// pml4, pdp, pd, pt
	struct mini_svm_guest_table *tables[4] = {NULL, NULL, NULL, NULL};
	void *pages[4] = {NULL, NULL, NULL, NULL};
	unsigned long *entry;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tables); ++i) {
		tables[i] = kzalloc(sizeof(struct mini_svm_guest_table), GFP_KERNEL);
		if (!tables[i]) {
			goto fail;
		}
		pages[i] = get_zeroed_page(GFP_KERNEL);
		if (!pages[i]) {
			goto fail;
		}
		tables[i]->entries = pages[i];
		tables[i]->num_entries = 1;
		tables[i]->type = MINI_GUEST_TABLE_TYPE_PML4 + i;
	}

	printk("ncr3.0 = %lx\n", virt_to_phys(tables[0]->entries));

	// Write pml4e
	entry = (unsigned long *)pages[0];
	entry[0] = mini_svm_create_entry(virt_to_phys(pages[1]), MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
	printk("ncr3.1 = %lx\n", entry[0]);

	// Write pdpe
	entry = (unsigned long *)pages[1];
	entry[0] = mini_svm_create_entry(virt_to_phys(pages[2]), MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
	printk("ncr3.2 = %lx\n", entry[0]);

	// Write pde
	entry = (unsigned long *)pages[2];
	entry[0] = mini_svm_create_entry(virt_to_phys(pages[3]), MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
	printk("ncr3.3 = %lx\n", entry[0]);

	// Write pte
	entry = (unsigned long *)pages[3];
	entry[0] = mini_svm_create_entry(virt_to_phys(vm_page), MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
	printk("ncr3.4 = %lx\n", entry[1]);

	return tables[0];

fail:
	for (i = 0; i < ARRAY_SIZE(tables); ++i) {
		if (tables[i]) {
			kfree(tables[i]);
		}
		if (pages[i]) {
			free_page(pages[i]);
		}
	}
	return NULL;
}

void destroy_mini_svm_guest_table(struct mini_svm_guest_table *root) {

}

