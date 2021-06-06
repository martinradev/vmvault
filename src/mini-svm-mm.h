#ifndef MINI_SVM_MM_H
#define MINI_SVM_MM_H

#include <linux/types.h>

struct mini_svm_guest_table_pd {
	/* All of these are 2MiB pages */
	u64 *va;
	u64 pa;

	struct page *memory_2mb_page[16];
	u64 memory_2mb_pa[16];
};

struct mini_svm_guest_table_pdp {
	u64 *va;
	u64 pa;
	struct mini_svm_guest_table_pd pd;
};

struct mini_svm_guest_table_pml4 {
	u64 *va;
	u64 pa;
	struct mini_svm_guest_table_pdp pdp;
};

struct mini_svm_mm {
	struct mini_svm_guest_table_pml4 pml4;
	void *phys_memory;
};

int mini_svm_create_mm(struct mini_svm_mm **mm);
void mini_svm_destroy_mm(struct mini_svm_mm *mm);

int mini_svm_construct_debug_mm_one_page(struct mini_svm_mm *mm);
void mini_svm_destroy_guest_table(struct mini_svm_mm *mm);

int mini_svm_mm_write_phys_memory(struct mini_svm_mm *mm, u64 phys_address, void *bytes, u64 num_bytes);

#endif // MINI_SVM_MM_H
