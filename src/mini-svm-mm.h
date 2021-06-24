#ifndef MINI_SVM_MM_H
#define MINI_SVM_MM_H

#include <linux/types.h>

// TODO: move to common area
#define MINI_SVM_MAX_PHYS_SIZE (64UL * 1024UL * 1024UL)

struct mini_svm_nested_table_pt {
	u64 *va;
	u64 pa;
};

struct mini_svm_nested_table_pd {
	u64 *va;
	u64 pa;
	struct mini_svm_nested_table_pt pde[512];
};

struct mini_svm_nested_table_pdp {
	u64 *va;
	u64 pa;
	struct mini_svm_nested_table_pd pd;
};

struct mini_svm_nested_table_pml4 {
	u64 *va;
	u64 pa;
	struct mini_svm_nested_table_pdp pdp;
};

struct mini_svm_mm {
	struct mini_svm_nested_table_pml4 pml4;
	u64 phys_as_size;
	struct page **phys_memory_pages;
	void *phys_map;
};

int mini_svm_create_mm(struct mini_svm_mm **mm);
void mini_svm_destroy_mm(struct mini_svm_mm *mm);

int mini_svm_construct_nested_table(struct mini_svm_mm *mm);
void mini_svm_destroy_nested_table(struct mini_svm_mm *mm);

int mini_svm_mm_write_phys_memory(struct mini_svm_mm *mm, u64 phys_address, void *bytes, u64 num_bytes);
int mini_svm_mm_write_virt_memory(struct mini_svm_mm *mm, u64 virt_address, void *bytes, u64 num_bytes);

int mini_svm_construct_1gb_gpt(struct mini_svm_mm *mm);

int mini_svm_allocate_phys_page(struct mini_svm_mm *mm, u64 phys_address);

#endif // MINI_SVM_MM_H
