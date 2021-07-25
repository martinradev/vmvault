#ifndef MINI_SVM_MM_H
#define MINI_SVM_MM_H

#include <linux/types.h>

#define MINI_SVM_MAX_PHYS_SIZE (2UL * 1024UL * 1024UL)

struct sevault_mini_nested_table_pt {
	u64 *va;
	u64 pa;
};

struct sevault_mini_nested_table_pd {
	u64 *va;
	u64 pa;
	struct sevault_mini_nested_table_pt pde[512];
};

struct sevault_mini_nested_table_pdp {
	u64 *va;
	u64 pa;
	struct sevault_mini_nested_table_pd pd;
};

struct sevault_mini_nested_table_pml4 {
	u64 *va;
	u64 pa;
	struct sevault_mini_nested_table_pdp pdp;
};

struct sevault_mini_mm {
	struct sevault_mini_nested_table_pml4 pml4;
	struct page **phys_memory_pages;
	void *phys_map;
};

int sevault_mini_create_mm(struct sevault_mini_mm **mm);
void sevault_mini_destroy_mm(struct sevault_mini_mm *mm);

int sevault_mini_mm_write_phys_memory(struct sevault_mini_mm *mm, u64 phys_address, void *bytes, u64 num_bytes);
int sevault_mini_mm_write_virt_memory(struct sevault_mini_mm *mm, u64 virt_address, void *bytes, u64 num_bytes);

int sevault_mini_allocate_phys_page(struct sevault_mini_mm *mm, u64 phys_address);

#endif // MINI_SVM_MM_H