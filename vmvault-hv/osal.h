#ifndef VMVAULT_OSAL_H
#define VMVAULT_OSAL_H

void *vmvault_alloc(unsigned int nbytes);
void vmvault_free(const void *addr);

void *vmvault_allocate_page();
void *vmvault_allocate_n_pages(unsigned int n);
void vmvault_free_n_pages(unsigned int n);

void *vmvault_map_pfn(unsigned long pfn, unsigned long length);
void vmvault_unmap_va(const void *va, unsigned long length);

#endif VMVAULT_OSAL_H
