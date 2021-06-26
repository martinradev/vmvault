#ifndef PHYS_ADDR_UTIL_H
#define PHYS_ADDR_UTIL_H

// Copied for convenience from https://github.com/farazsth98/hypervisor_research_notes/

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

static int pagemap;

uint32_t page_offset(const uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(const void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(pagemap, offset, SEEK_SET);
    read(pagemap, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(const void *addr)
{
    if (!pagemap) {
        pagemap = open("/proc/self/pagemap", O_RDONLY);

        if (pagemap == -1) {
            printf("[!] Cannot open /proc/self/pagemap!\n");
            exit(-1);
        }
    }

    const uint64_t gfn = gva_to_gfn(addr);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

#endif // PHYS_ADDR_UTIL_H
