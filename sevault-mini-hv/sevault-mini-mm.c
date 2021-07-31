// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "sevault-mini-mm.h"
#include "sevault-mini.h"

#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/io.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

// FIXME: Couldn't figure out how to find out the maximum pfn from a kernel module.
//        These bounds are well-defined in the kernel but don't seem to be exposed to modules.
//        Check max_pfn
//        I do not expect the host to have more than 256 gigs.
#define HOST_MAX_PHYS_MEMORY_IN_GIGS 256

int sevault_mini_mm_write_phys_memory(struct sevault_mini_mm *mm, u64 phys_address, void *bytes, u64 num_bytes) {
	if (phys_address + num_bytes > MINI_SVM_MAX_PHYS_SIZE) {
		return -EINVAL;
	}
	memcpy((unsigned char *)mm->phys_map + phys_address, bytes, num_bytes);
	return 0;
}

static void sevault_mini_destroy_nested_table(struct sevault_mini_mm *mm);

static int sevault_mini_construct_nested_table(struct sevault_mini_mm *mm) {
	int r;
	size_t num_done_entries = 0;
	size_t pde_index;
	size_t pte_index;
	size_t page_i;
	const size_t num_pages = (MINI_SVM_MAX_PHYS_SIZE / MINI_SVM_4KB);
	struct sevault_mini_nested_table_pml4 *pml4 = &mm->pml4;
	const u64 one_gig = 1024UL * 1024UL * 1024UL;

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
	memset(mm->phys_map, 0, MINI_SVM_MAX_PHYS_SIZE);

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
	pml4->va[0] = sevault_mini_create_entry(pml4->pdp.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);

	// Create pd
	pml4->pdp.pd.va = (void *)get_zeroed_page(GFP_KERNEL);
	if (!pml4->pdp.pd.va) {
		r = -ENOMEM;
		goto fail;
	}
	pml4->pdp.pd.pa = virt_to_phys(pml4->pdp.pd.va);
	pml4->pdp.va[0] = sevault_mini_create_entry(pml4->pdp.pd.pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);

	// Fill PDEs
	for (pde_index = 0; pde_index < 512U && num_done_entries < num_pages; ++pde_index) {
		struct sevault_mini_nested_table_pt* pt = &pml4->pdp.pd.pde[pde_index];
		pt->va = (void *)get_zeroed_page(GFP_KERNEL);
		if (!pt->va) {
			r = -ENOMEM;
			goto fail;
		}
		pt->pa = virt_to_phys(pt->va);
		pml4->pdp.pd.va[pde_index] = sevault_mini_create_entry(pt->pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
		// Fill PTEs
		for (pte_index = 0; pte_index < 512U && num_done_entries < num_pages; ++pte_index) {
			u64 pte_pa = page_to_phys(mm->phys_memory_pages[num_done_entries]);
			pt->va[pte_index] = sevault_mini_create_entry(pte_pa, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK);
			++num_done_entries;
		}
	}

	// Map all of host physical memory to the VM.
	for (page_i = 0; page_i < HOST_MAX_PHYS_MEMORY_IN_GIGS; ++page_i) {
		pml4->pdp.va[1 + page_i] = sevault_mini_create_entry(one_gig * page_i, MINI_SVM_PRESENT_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_USER_MASK | MINI_SVM_LEAF_MASK);
	}

	return 0;

fail:
	sevault_mini_destroy_nested_table(mm);
	return r;
}

static void sevault_mini_destroy_nested_table(struct sevault_mini_mm *mm) {
	size_t i;
	const size_t num_pages = MINI_SVM_MAX_PHYS_SIZE / MINI_SVM_4KB;
	struct sevault_mini_nested_table_pml4 *pml4 = &mm->pml4;

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
			free_page((unsigned long)pml4->pdp.pd.pde[i].va);
		}
	}

	vunmap(mm->phys_map);

	for (i = 0; i < num_pages; ++i) {
		if (mm->phys_memory_pages[i]) {
			__free_page(mm->phys_memory_pages[i]);
		}
	}

	mm->phys_memory_pages = NULL;
}

static int sevault_mini_construct_gpt(struct sevault_mini_mm *mm) {
	// We just need 2 pages for the page table, which will start at physical address 0 and will have length of 1gig.
	const __u64 pml4e = sevault_mini_create_entry(0x1000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	const __u64 pdpe = sevault_mini_create_entry(0x2000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	const __u64 pde = sevault_mini_create_entry(0x3000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	const u64 one_gig = 1024UL * 1024UL * 1024UL;
	size_t i;
	int r = 0;

	if ((r = sevault_mini_mm_write_phys_memory(mm, 0x0, (void *)&pml4e, sizeof(pml4e))) != 0) {
		return r;
	}
	if ((r = sevault_mini_mm_write_phys_memory(mm, 0x1000, (void *)&pdpe, sizeof(pdpe))) != 0) {
		return r;
	}
	if ((r = sevault_mini_mm_write_phys_memory(mm, 0x2000, (void *)&pde, sizeof(pde))) != 0) {
		return r;
	}

	// Create image ptes
	for (i = 0; i < 8UL; ++i) {
		const __u64 image_pte = sevault_mini_create_entry(0x4000 + 0x1000 * i, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if ((r = sevault_mini_mm_write_phys_memory(mm, 0x3000 + 8UL * (4UL + i), (void *)&image_pte, sizeof(image_pte))) != 0) {
			return r;
		}
	}

	// Write stack pte
	if ((nr_cpu_ids + 1UL) * 0x400UL > 0x10000UL) {
		printk("Not enough memory for all stacks: %u\n", nr_cpu_ids);
		return -ENOMEM;
	}
	for (i = 0; i < 16U; ++i) {
		const __u64 stack_pte = sevault_mini_create_entry(0x10000 + i * 0x1000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if ((r = sevault_mini_mm_write_phys_memory(mm, 0x3000 + 8UL * (16UL + i), (void *)&stack_pte, sizeof(stack_pte))) != 0) {
			return r;
		}
	}

	// Create keys ptes
	for (i = 0; i < 15UL; ++i) {
		const __u64 keys_pte = sevault_mini_create_entry(0x20000 + 0x1000 * i, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if ((r = sevault_mini_mm_write_phys_memory(mm, 0x3000 + 8UL * (32 + i), (void *)&keys_pte, sizeof(keys_pte))) != 0) {
			return r;
		}
	}

	// Create comm block ptes
	for (i = 0; i < nr_cpu_ids; ++i) {
		const __u64 comm_block_pte = sevault_mini_create_entry(0x30000 + i * 0x1000UL, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if ((r = sevault_mini_mm_write_phys_memory(mm, 0x3000 + 8UL * (48 + i), (void *)&comm_block_pte, sizeof(comm_block_pte))) != 0) {
			return r;
		}
	}

	// Direct-map host pages.
	for (i = 0; i < HOST_MAX_PHYS_MEMORY_IN_GIGS; ++i) {
		const __u64 pdpe = sevault_mini_create_entry(one_gig * (i + 1UL), MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_LEAF_MASK);
		if ((r = sevault_mini_mm_write_phys_memory(mm, 0x1000UL + 0x8UL * (i + 1UL), (void *)&pdpe, sizeof(pdpe))) != 0) {
			return r;
		}
	}
	return 0;
}

int sevault_mini_create_mm(struct sevault_mini_mm **out_mm) {
	struct sevault_mini_mm *mm = NULL;
	int r;

	mm = kzalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm) {
		r = -ENOMEM;
		goto fail;
	}

	r = sevault_mini_construct_nested_table(mm);
	if (r) {
		kfree(mm);
		goto fail;
	}

	r = sevault_mini_construct_gpt(mm);
	if (r) {
		sevault_mini_destroy_nested_table(mm);
		kfree(mm);
		goto fail;
	}

	*out_mm = mm;

	return 0;

fail:
	return r;
}

void sevault_mini_destroy_mm(struct sevault_mini_mm *mm) {
	BUG_ON(!mm);

	kfree(mm);
}

