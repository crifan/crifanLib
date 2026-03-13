/*
    File: machOUtil.c
    Function: Mach-O binary utilities implementation
    Author: Crifan Li
    Updated: 20260313_1732
*/

#include "machOUtil.h"

/*==============================================================================
 Mach-O
==============================================================================*/

// Parse Mach-O load commands to get total mapped size of an image
uintptr_t getMachOImageSize(const struct mach_header *header, intptr_t slide) {
    if (!header) return 0x40000; // 256KB fallback
    
    uintptr_t base = (uintptr_t)header;
    uintptr_t maxEnd = base;
    
    if (header->magic == MH_MAGIC_64) {
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)header;
        const uint8_t *ptr = (const uint8_t *)(h64 + 1);
        for (uint32_t i = 0; i < h64->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;
                uintptr_t segEnd = seg->vmaddr + slide + seg->vmsize;
                if (segEnd > maxEnd) maxEnd = segEnd;
            }
            ptr += lc->cmdsize;
        }
    }
    
    return (maxEnd > base) ? (maxEnd - base) : 0x40000;
}
