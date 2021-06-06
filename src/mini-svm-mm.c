#include "mini-svm-mm.h"

#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/io.h>
#include <linux/vmalloc.h>

static const __u64 MINI_SVM_PRESENT_MASK = 0x1UL;
static const __u64 MINI_SVM_WRITEABLE_MASK = 0x2UL;
static const __u64 MINI_SVM_USER_MASK = 0x4UL;
static const __u64 MINI_SVM_PDE_LEAF_MASK = (1UL << 7U);

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

	mini_svm_destroy_guest_table(mm);
	kfree(mm);
}

int mini_svm_construct_debug_mm_one_page(struct mini_svm_mm *mm) {
	int r;
	int i;
	struct mini_svm_guest_table_pml4 *pml4 = &mm->pml4;

	pml4->va = get_zeroed_page(GFP_KERNEL);
	if (!pml4->va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pa = virt_to_phys(pml4->va);

	pml4->pdp.va = get_zeroed_page(GFP_KERNEL);
	if (!pml4->pdp.va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pdp.pa = virt_to_phys(pml4->pdp.va);

	pml4->pdp.pd.va = get_zeroed_page(GFP_KERNEL);
	if (!pml4->pdp.pd.va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pdp.pd.pa = virt_to_phys(pml4->pdp.pd.va);

	for (i = 0; i < ARRAY_SIZE(pml4->pdp.pd.memory_2mb_page); ++i) {
		pml4->pdp.pd.memory_2mb_page[i] = alloc_pages(GFP_KERNEL, get_order(2 * 1024 * 1024));
		if (!pml4->pdp.pd.memory_2mb_page[i]) {
			r = -ENOMEM;
			goto fail;
		}
		pml4->pdp.pd.memory_2mb_pa[i] = page_to_pfn(pml4->pdp.pd.memory_2mb_page[i]) << 12;
	}

	mm->phys_memory = vmap(pml4->pdp.pd.memory_2mb_page, ARRAY_SIZE(pml4->pdp.pd.memory_2mb_page), VM_MAP, PAGE_KERNEL);
	if (!mm->phys_memory) {
		goto fail;
	}

	pml4->va[0] = mini_svm_create_entry(pml4->pdp.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
	pml4->pdp.va[0] = mini_svm_create_entry(pml4->pdp.pd.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);

	for (i = 0; i < ARRAY_SIZE(pml4->pdp.pd.memory_2mb_page); ++i) {
		pml4->pdp.pd.va[i] = mini_svm_create_entry(pml4->pdp.pd.memory_2mb_pa[i], MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK | MINI_SVM_PDE_LEAF_MASK);
	}

	return 0;

fail:
	if (mm->phys_memory) {
		vunmap(mm->phys_memory);
	}
	if (pml4->va) {
		free_page(pml4->va);
	}
	if (pml4->pdp.va) {
		free_page(pml4->pdp.va);
	}
	if (pml4->pdp.pd.va) {
		free_page(pml4->pdp.pd.va);
	}
	for (i = 0; i < ARRAY_SIZE(pml4->pdp.pd.memory_2mb_page); ++i) {
		if (pml4->pdp.pd.memory_2mb_page[i]) {
			free_page(pml4->pdp.pd.memory_2mb_page[i]);
		}
	}
	return r;
}

void mini_svm_destroy_guest_table(struct mini_svm_mm *mm) {
	int i;
	struct mini_svm_guest_table_pml4 *pml4 = &mm->pml4;

	if (pml4->va) {
		free_page(pml4->va);
	}
	if (pml4->pdp.va) {
		free_page(pml4->pdp.va);
	}
	if (pml4->pdp.pd.va) {
		free_page(pml4->pdp.pd.va);
	}
	for (i = 0; i < ARRAY_SIZE(pml4->pdp.pd.memory_2mb_page); ++i) {
		if (pml4->pdp.pd.memory_2mb_page[i]) {
			free_pages(pml4->pdp.pd.memory_2mb_page[i], get_order(2 * 1024 * 1024));
		}
	}
}

int mini_svm_mm_write_phys_memory(struct mini_svm_mm *mm, u64 phys_address, void *bytes, u64 num_bytes) {
	void *page_2mb_va;
	unsigned int page_index;
	unsigned int page_offset;
	if (phys_address + num_bytes > 32U * 1024U * 1024U) {
		return -EINVAL;
	}

	memcpy((u8*)mm->phys_memory + phys_address, bytes, num_bytes);

	return 0;
}

