/*
    File: machOUtil.h
    Function: Mach-O binary utilities
    Author: Crifan Li
    Updated: 20260313_1732
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef machOUtil_h
#define machOUtil_h

#include <stdint.h>
#include <mach-o/loader.h>

// Parse Mach-O load commands to calculate total virtual memory mapped size of a loaded image
// header: pointer to the mach_header of the loaded image
// slide: ASLR slide value (from _dyld_get_image_vmaddr_slide)
// returns: total mapped size in bytes, or 0x40000 (256KB) as fallback
uintptr_t getMachOImageSize(const struct mach_header *header, intptr_t slide);

#endif /* machOUtil_h */

#ifdef __cplusplus
}
#endif
