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
