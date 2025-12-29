#define FILE_MAP_OFFSET = p_offset & ~(PAGESZ-1)
#define seg_page_vaddr = p_vaddr & ~(PAGESZ-1)
#define fdeleta = p_vaddr & (PAGESZ-1)
#define fdeltao = p_offset & (PAGESZ-1)
