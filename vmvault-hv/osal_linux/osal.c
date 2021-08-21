#include "../osal.h"

#define SMALL_PAGE_SIZE 0x1000

void *vmvault_alloc(unsigned int nbytes)
{
	return kmalloc(nbytes, GFP_KERNEL);
}

void vmvault_free(const void *addr)
{
	kfree(addr);
}

void *vmvault_allocate_page(unsigned int n)
{
	return vmalloc(
}

void *vmvault_allocate_n_pages(unsigned int n)
{
	return vmalloc(n * SMALL_PAGE_SIZE, GFP_KERNEL);
}

void vmvault_free_n_pages(void *pages, unsigned int n)
{
	vfree(pages);
}
