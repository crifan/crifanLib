/*
    File: CrifanLib.h
    Function: crifan's common C libs header file
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/CrifanLib.h
    Updated: 20211209_1554
*/

// This will not work with all C++ compilers, but it works with clang and gcc
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CrifanLib_h
#define CrifanLib_h

//#import <os/log.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>
//#include <regex.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <limits.h> /* PATH_MAX */
#include <errno.h>
#include <ctype.h>
#include <dlfcn.h>

// integer
bool isIntInList(int valueToCheck, int* intList, int intListLen);

// string
char* boolToStr(bool curBool);
char* strToLowercase(const char* origStr);
bool strStartsWith(const char *fullStr, const char *prefixStr);
bool strEndsWith(const char* fullStr, const char* endStr);
char* removeHead(const char* fullStr, const char* headStr);
char* removeTail(const char* fullStr, const char* tailStr);
char* removeEndSlash(const char* origPath);
char* strReplace(const char *fullStr, const char *replaceFromStr, const char *replaceToStr);
void strSplit(const char* fullStr, const char* delim, char*** resultSubStrListPtr, int* resultListLenPtr);

// file size
long calulateFilesize_fgetc(char* inputFilename);
long calulateFilesize_ftell(char* inputFilename);
long calulateFilesize_fstat(char* inputFilename);

// file mode
char* fileSizeToStr(off_t fileStSize);
void fileModeToStr(mode_t mode, char * modeStrBuf);
char* fileTypeToChar(mode_t mode);
char* statToStr(struct stat* statInfo);

// file path
char* removeTwoDotPart(const char* origPath);
bool isPathEaqual(const char* path1, const char* path2);
char* toPurePath(const char* origPath);
bool parseRealPath(const char* curPath, char* gotRealPath);

// iOS: system
int iOS_system(const char* command);

#endif /* CrifanLib_h */

#ifdef __cplusplus
}
#endif
