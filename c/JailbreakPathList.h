/*
    File: JailbreakPathList.h
    Function: crifan's common jailbreak file path list header file
    Author: Crifan Li
    Updated: 20211125_1558
*/

// This will not work with all C++ compilers, but it works with clang and gcc
#ifdef __cplusplus
extern "C" {
#endif

#ifndef JailbreakPathList_h
#define JailbreakPathList_h

#include <stdbool.h>

#include "CrifanLib.h"

extern const char* jailbreakFilePathList[];
extern int jailbreakPathListLen;

bool isJailbreakPath(const char *pathname);
bool isJailbreakPath_pureC(const char *curPath);
bool isJailbreakPath_realpath(const char *pathname);

#endif /* JailbreakPathList_h */

#ifdef __cplusplus
}
#endif
