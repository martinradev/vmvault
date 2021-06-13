#include "mini-svm-mm.h"

#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/io.h>
#include <linux/vmalloc.h>

#define MINI_SVM_4KB (4096UL)
#define MINI_SVM_2MB (512UL * MINI_SVM_4KB)
#define MINI_SVM_1GB (512UL * MINI_SVM_2MB)
#define MINI_SVM_512GB (512UL * MINI_SVM_1GB)

static const __u64 MINI_SVM_PRESENT_MASK = 0x1UL;
static const __u64 MINI_SVM_WRITEABLE_MASK = 0x2UL;
static const __u64 MINI_SVM_USER_MASK = 0x4UL;
static const __u64 MINI_SVM_LEAF_MASK = (1UL << 7U);

static __u64 mini_svm_create_entry(__u64 pa, __u64 mask) {
	return pa | mask;
}

int mini_svm_create_mm(struct mini_svm_mm **out_mm) {
	struct mini_svm_mm *mm = NULL;
	int r;

	mm = kzalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm) {
		r = -ENOMEM;
		goto fail;
	}

	*out_mm = mm;

	return 0;

fail:
	return r;
}

void mini_svm_destroy_mm(struct mini_svm_mm *mm) {
	BUG_ON(!mm);

	mini_svm_destroy_nested_table(mm);
	kfree(mm);
}

int mini_svm_construct_nested_table(struct mini_svm_mm *mm) {
	int r;
	size_t num_done_entries = 0;
	size_t pde_index;
	size_t pte_index;
	size_t page_i;
	const size_t num_pages = (mm->phys_as_size / MINI_SVM_4KB);
	struct mini_svm_nested_table_pml4 *pml4 = &mm->pml4;

	if (mm->phys_as_size > MINI_SVM_MAX_PHYS_SIZE ||
		mm->phys_as_size % MINI_SVM_4KB != 0ULL) {
		return -EINVAL;
	}

	mm->phys_memory_pages = (struct page **)vmalloc(num_pages * sizeof(struct page *));
	if (!mm->phys_memory_pages) {
		r = -ENOMEM;
		goto fail;
	}
	memset(mm->phys_memory_pages, 0, num_pages * sizeof(struct page *));

	for (page_i = 0; page_i < num_pages; ++page_i) {
		mm->phys_memory_pages[page_i] = alloc_page(GFP_KERNEL);
		if (!mm->phys_memory_pages[page_i]) {
			r = -ENOMEM;
			goto fail;
		}
	}

	mm->phys_map = vmap(mm->phys_memory_pages, num_pages, VM_MAP, PAGE_KERNEL);
	if (!mm->phys_map) {
		r = -ENOMEM;
		goto fail;
	}
	memset(mm->phys_map, 0, mm->phys_as_size);

	// Create root.
	pml4->va = (void *)get_zeroed_page(GFP_KERNEL);
	if (!pml4->va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pa = virt_to_phys(pml4->va);

	// Create pdp
	pml4->pdp.va = (void *)get_zeroed_page(GFP_KERNEL);
	if (!pml4->pdp.va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pdp.pa = virt_to_phys(pml4->pdp.va);
	pml4->va[0] = mini_svm_create_entry(pml4->pdp.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);

	// Create pd
	pml4->pdp.pd.va = (void *)get_zeroed_page(GFP_KERNEL);
	if (!pml4->pdp.pd.va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pdp.pd.pa = virt_to_phys(pml4->pdp.pd.va);
	pml4->pdp.va[0] = mini_svm_create_entry(pml4->pdp.pd.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);

	// Fill PDEs
	for (pde_index = 0; pde_index < 512U && num_done_entries < num_pages; ++pde_index) {
		struct mini_svm_nested_table_pt* pt = &pml4->pdp.pd.pde[pde_index];
		pt->va = (void *)get_zeroed_page(GFP_KERNEL);
		if (!pt->va) {
			r = -ENOMEM;
			goto fail;
		}
		pt->pa = virt_to_phys(pt->va);
		pml4->pdp.pd.va[pde_index] = mini_svm_create_entry(pt->pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
		// Fill PTEs
		for (pte_index = 0; pte_index < 512U && num_done_entries < num_pages; ++pte_index) {
			u64 pte_pa = page_to_phys(mm->phys_memory_pages[num_done_entries]);
			pt->va[pte_index] = mini_svm_create_entry(pte_pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
			++num_done_entries;
		}
	}

	return 0;

fail:
	mini_svm_destroy_nested_table(mm);
	return r;
}

void mini_svm_destroy_nested_table(struct mini_svm_mm *mm) {
	size_t i;
	const size_t num_pages = mm->phys_as_size / MINI_SVM_4KB;
	struct mini_svm_nested_table_pml4 *pml4 = &mm->pml4;

	if (pml4->va) {
		free_page((unsigned long)pml4->va);
	}
	if (pml4->pdp.va) {
		free_page((unsigned long)pml4->pdp.va);
	}
	if (pml4->pdp.pd.va) {
		free_page((unsigned long)pml4->pdp.pd.va);
	}

	for (i = 0; i < 512U; ++i) {
		if (pml4->pdp.pd.pde[i].va) {
			free_page(pml4->pdp.pd.pde[i].va);
		}
	}

	for (i = 0; i < num_pages; ++i) {
		if (mm->phys_memory_pages[i]) {
			__free_page(mm->phys_memory_pages[i]);
		}
	}
}

// The start of guest physical memory is for the GPT which currently just takes two physical pages
// Writes to memory at an address lower than this one should be forbidden when they go via write_virt_memory.
#define PHYS_BASE_OFFSET 0x3000U

int mini_svm_mm_write_virt_memory(struct mini_svm_mm *mm, u64 virt_address, void *bytes, u64 num_bytes) {
	if (virt_address < PHYS_BASE_OFFSET) {
		return -EINVAL;
	}
	return mini_svm_mm_write_phys_memory(mm, virt_address, bytes, num_bytes);
}

int mini_svm_mm_write_phys_memory(struct mini_svm_mm *mm, u64 phys_address, void *bytes, u64 num_bytes) {
	if (phys_address + num_bytes > MINI_SVM_2MB) {
		return -EINVAL;
	}

	memcpy((unsigned char *)mm->phys_map + phys_address, bytes, num_bytes);

	return 0;
}

int mini_svm_construct_1gb_gpt(struct mini_svm_mm *mm) {
	// We just need 2 pages for the page table, which will start at physical address 0 and will have length of 1gig.
	const u64 pml4e = mini_svm_create_entry(0x1000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	const u64 pdpe = mini_svm_create_entry(0x0, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_LEAF_MASK);
	int r;

	r = mini_svm_mm_write_phys_memory(mm, 0, (void *)&pml4e, sizeof(pml4e));
	if (r) {
		return r;
	}
	mini_svm_mm_write_phys_memory(mm, 0x1000, (void *)&pdpe, sizeof(pdpe));
	if (r) {
		return r;
	}
	return 0;
}

int mini_svm_allocate_phys_page(struct mini_svm_mm *mm, u64 phys_address) {
	u64 rest;
	u64 pml4e = (phys_address / MINI_SVM_512GB);
	rest = phys_address % MINI_SVM_512GB;
	u64 pdpe = (rest / MINI_SVM_1GB);
	rest = rest % MINI_SVM_1GB;
	u64 pde = (rest / MINI_SVM_2MB);
	rest = rest % MINI_SVM_2MB;
	u64 pte = (rest / MINI_SVM_4KB);


	return 0;
}
