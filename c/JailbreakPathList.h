/*
    File: JailbreakPathList.h
    Function: crifan's common jailbreak file path list header file
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/JailbreakPathList.h
    Updated: 20260313_1732
*/

// This will not work with all C++ compilers, but it works with clang and gcc
#ifdef __cplusplus
extern "C" {
#endif

#ifndef JailbreakPathList_h
#define JailbreakPathList_h

#include <stdbool.h>

#include "CrifanLib.h"

extern const int jailbreakPathListLen;
extern const char* jailbreakPathList_Dylib[];
extern const char* jailbreakPathList_Other[];
//extern char* jailbreakPathList_Dylib[];
//extern char* jailbreakPathList_Other[];
extern const int jailbreakPathListLen_Dylib;
extern const int jailbreakPathListLen_Other;

//extern const char* jailbreakPathList[];
const char** getJailbreakPathList(void);
//char** getJailbreakPathList(void);

bool isPathInJailbreakPathList(const char *curPath);
bool isJailbreakPath_pureC(const char *curPath);
bool isJailbreakPath_realpath(const char *pathname);
bool isJailbreakPath(const char *pathname);
bool isJailbreakDylib(const char *pathname);
bool isJailbreakDylibFunctionName(const char *libFuncName);

bool isPathInList(
      const char* inputPath,
//      char* inputPath,
      const char** pathList,
//      char** pathList,
      int pathListLen,
      bool isConvertToPurePath, // is convert to pure path or not
      bool isCmpSubFolder // is compare sub foder or not
);

/*==============================================================================
 Zero-Allocation Fast Path Matching (for hook hot paths)

 Designed for file system hook hot paths (open/access/fopen/readlink).
 Uses only strcmp/strncmp, zero malloc/free calls.

 Why: The original isJailbreakPath() -> isPathInJailbreakPathList() chain
 allocates ~1000x malloc/free per call (getJailbreakPathList + toPurePath +
 isPathEqual). When hooks fire thousands of times at startup, this causes
 heap corruption (EXC_BAD_ACCESS) in MALLOC_NANO.

 These static inline functions are kept in the header for zero-overhead
 inlining at call sites.
==============================================================================*/

// Zero-allocation path list matching: check if path starts with any entry in list
static inline bool matchesPathList(const char *path, const char **list, int listLen) {
    for (int i = 0; i < listLen; i++) {
        const char *jbPath = list[i];
        size_t jbLen = strlen(jbPath);
        if (jbLen == 0) continue;
        if (strncmp(path, jbPath, jbLen) == 0) {
            char after = path[jbLen];
            // Exact match (after=='\0'), or subdirectory (after=='/'), or jbPath ends with '/'
            if (after == '\0' || after == '/' || jbPath[jbLen - 1] == '/') {
                return true;
            }
        }
    }
    return false;
}

// Zero-allocation fast jailbreak path check (combines Dylib + Other lists)
static inline bool isJailbreakPath_fast(const char *path) {
    if (!path || !*path) return false;
    return matchesPathList(path, jailbreakPathList_Dylib, jailbreakPathListLen_Dylib)
        || matchesPathList(path, jailbreakPathList_Other, jailbreakPathListLen_Other);
}

#endif /* JailbreakPathList_h */

#ifdef __cplusplus
}
#endif
