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

#ifndef VMVAULT_MM_H
#define VMVAULT_MM_H

#include <linux/types.h>

#define VMVAULT_MAX_PHYS_SIZE (2UL * 1024UL * 1024UL)

struct vmvault_nested_table_pt {
	u64 *va;
	u64 pa;
};

struct vmvault_nested_table_pd {
	u64 *va;
	u64 pa;
	struct vmvault_nested_table_pt pde[512];
};

struct vmvault_nested_table_pdp {
	u64 *va;
	u64 pa;
	struct vmvault_nested_table_pd pd;
};

struct vmvault_nested_table_pml4 {
	u64 *va;
	u64 pa;
	struct vmvault_nested_table_pdp pdp;
};

struct vmvault_mm {
	struct vmvault_nested_table_pml4 pml4;
	struct page **phys_memory_pages;
	size_t num_pages;
	void *phys_map;
	void *comm_block_memory;
};

int vmvault_create_mm(struct vmvault_mm **mm);
void vmvault_destroy_mm(struct vmvault_mm *mm);

int vmvault_mm_write_phys_memory(struct vmvault_mm *mm, u64 phys_address, void *bytes, u64 num_bytes);
int vmvault_mm_write_virt_memory(struct vmvault_mm *mm, u64 virt_address, void *bytes, u64 num_bytes);

int vmvault_allocate_phys_page(struct vmvault_mm *mm, u64 phys_address);

int vmvault_mm_mark_vm_memory_inaccessible(struct vmvault_mm *mm);

#endif // VMVAULT_MM_H
