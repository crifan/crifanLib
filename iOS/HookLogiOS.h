/*
    File: HookLogiOS.h
    Function: crifan's common iOS hook log functions header
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/HookLogiOS.h
    Updated: 20260120_1748
*/

// This will not work with all C++ compilers, but it works with clang and gcc
#ifdef __cplusplus
extern "C" {
#endif

#ifndef HookLogiOS_h
#define HookLogiOS_h


#import <Foundation/Foundation.h>
#import <os/log.h>

/*==============================================================================
 Global Config
==============================================================================*/

// Note: os_log max length/limit is 1K=1024
// when split large NSString, for single line string length will use this definition
extern int LOG_MAX_LEN_ONCE;

// output one log every N time
extern long LOG_ONCE_PER_NUM;

/*==============================================================================
 Global Variable
==============================================================================*/

extern long gCurLogNum;

extern long gNoUse;

/*==============================================================================
 Functions
==============================================================================*/

bool nonEmptyHeader(id _Nullable curHeaderDict);
void logLargeStr(NSString* _Nonnull largeStr);
void logPossibleLargeStr(NSString* _Nonnull possibleLargeStr);
void printCallStack(NSString* _Nullable prefix);
void printCallStack_largeStr(NSString* _Nullable prefix);

void dbgWriteClsDescToFile(char* _Nonnull className, id _Nonnull classObj);

/*==============================================================================
 Common Define
==============================================================================*/

@interface NSObject (CrifanDebug)
- (nullable id)_ivarDescription;
- (nullable id)_propertyDescription;
- (nullable id)_methodDescription;
- (nullable id)_shortMethodDescription;
@end

// String
#define STR_EMPTY ""
#define IS_EMPTY_STR(curStr) (0 == strcmp(curStr, STR_EMPTY))

// Log

#define ERROR_STR(curErr) ((error != NULL) ? *error: @"")

#define HOOK_PREFIX(isEnable) (isEnable ? "":"no_hook ")

//#ifdef FOR_RELEASE
#ifdef DISABLE_ALL_IOS_LOG

//// for debug
//#define IOS_LOG_INFO_ENABLE     1
#define IOS_LOG_INFO_ENABLE     0

#define IOS_LOG_DEBUG_ENABLE    0
#define IOS_LOG_ERROR_ENABLE    0

#else

#define IOS_LOG_INFO_ENABLE     1
#define IOS_LOG_DEBUG_ENABLE    0
#define IOS_LOG_ERROR_ENABLE    1

#endif

//// hook_openFile.xm -> hook_openFile
//#define FILENAME_NO_SUFFIX (strrchr(__FILE_NAME__, '.') ? strrchr(__FILE_NAME__, '.') + 1 : __FILE_NAME__)

// // _logos_function$_ungrouped$open -> open
// #define PURE_FUNC (strrchr(__func__, '$') ? strrchr(__func__, '$') + 1 : __func__)

// // _logos_method$_ungrouped$NSFileManager$fileExistsAtPath$ -> fileExistsAtPath$


#define UNGROUP_STR "_ungrouped$"
#define UNGROUP_LEN strlen(UNGROUP_STR)
#define HOOK_ "hook_"
//#define HOOK_SPACE "hook_ "

// Method 1:
// // _logos_method$_ungrouped$NSFileManager$fileExistsAtPath$ -> NSFileManager$fileExistsAtPath$
// //#define FUNC_UNGROUPED_NEXT (0 == strcmp(PURE_FUNC, "")) ? (strstr(__func__, UNGROUP_STR) + UNGROUP_LEN) : (PURE_FUNC)
// #define FUNC_UNGROUPED_NEXT IS_EMPTY_STR(PURE_FUNC) ? (strstr(__func__, UNGROUP_STR) + UNGROUP_LEN) : (PURE_FUNC)

// // NSFileManager$fileExistsAtPath$ -> fileExistsAtPath$
// // #define FUNC_ONLY_METHOD strchr(FUNC_UNGROUPED_NEXT, '$') ? (strchr(FUNC_UNGROUPED_NEXT, '$') + 1) : __func__
// // #define FUNC_ONLY_METHOD (NULL != strchr(FUNC_UNGROUPED_NEXT, '$')) ? (strchr(FUNC_UNGROUPED_NEXT, '$') + 1) : __func__
// #define FUNC_ONLY_METHOD strchr(FUNC_UNGROUPED_NEXT, '$') ? (strchr(FUNC_UNGROUPED_NEXT, '$') + 1) : FUNC_UNGROUPED_NEXT


// Method 2:
#define FUNC_NAME_AFTER_UNGROUP strstr(__func__, UNGROUP_STR) ? (strstr(__func__, UNGROUP_STR) + UNGROUP_LEN) : __func__
// =>
// _logos_function$_ungrouped$open -> open
// _logos_method$_ungrouped$NSFileManager$fileExistsAtPath$ -> NSFileManager$fileExistsAtPath$
// normal_function -> normal_function

//#define FUNC_NAME strchr(FUNC_NAME_AFTER_UNGROUP, '$') ? (strchr(FUNC_NAME_AFTER_UNGROUP, '$') + 1) : FUNC_NAME_AFTER_UNGROUP
//#define FUNC_NAME_NO_CLASS strchr(FUNC_NAME_AFTER_UNGROUP, '$') ? (strchr(FUNC_NAME_AFTER_UNGROUP, '$') + 1) : FUNC_NAME_AFTER_UNGROUP
// =>
// open -> open
// NSFileManager$fileExistsAtPath$ -> fileExistsAtPath$
// normal_function -> normal_function

// Updated: add support for `_logos_meta_method` inside hook_aweme.mm
// static BOOL _logos_meta_method$_ungrouped$TTInstallUtil$isJailBroken(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL);
#define FUNC_NAME_NO_CLASS FUNC_NAME_AFTER_UNGROUP

#define FUNC_NAME strchr(FUNC_NAME_NO_CLASS, ' ') ? (strchr(FUNC_NAME_NO_CLASS, ' ') + 1) : FUNC_NAME_NO_CLASS
// =>
// +[CrifanLibHookiOS nsStrListToStr:isSortList:isAddIndexPrefix:] -> nsStrListToStr:isSortList:isAddIndexPrefix:]

#define HOOK_FILE_NAME strstr(__FILE_NAME__, HOOK_) ? __FILE_NAME__ : (HOOK_ " " __FILE_NAME__)
// =>
// hook_aweme.xm -> hook_aweme.xm
// CrifanLibHookiOS.m -> hook_ CrifanLibHookiOS.m

#define iosLogInfo(format, ...) \
    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, HOOK_FILE_NAME, FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, FUNC_ONLY_METHOD, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, FUNC_UNGROUPED_NEXT, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, PURE_FUNC, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, FILENAME_NO_SUFFIX, PURE_FUNC, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_INFO_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, __func__, __VA_ARGS__); } while(0)

#define iosLogDebug(format, ...) \
do { if (IOS_LOG_DEBUG_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, HOOK_FILE_NAME,  FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_DEBUG_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__,  FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_DEBUG_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__,  PURE_FUNC, __VA_ARGS__); } while(0)

#define iosLogError(format, ...) \
do { if (IOS_LOG_ERROR_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, HOOK_FILE_NAME, FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_ERROR_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, FUNC_NAME, __VA_ARGS__); } while(0)
//    do { if (IOS_LOG_ERROR_ENABLE) os_log(OS_LOG_DEFAULT, "%s %s: " format, __FILE_NAME__, PURE_FUNC, __VA_ARGS__); } while(0)


NS_ASSUME_NONNULL_BEGIN

@interface HookLogiOS : NSObject

@end

NS_ASSUME_NONNULL_END


#endif /* HookLogiOS_h */

#ifdef __cplusplus
}
#endif
