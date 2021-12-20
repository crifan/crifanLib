/*
    File: CrifanLibiOS.h
    Function: crifan's common iOS function
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/CrifanLibiOS.h
    Updated: 20211215_1125
*/

#import <Foundation/Foundation.h>

#import "CrifanLib.h"

extern const int OPEN_OK;
extern const int OPEN_FAILED;

extern const int OPEN_FD_INVALID;

typedef NS_ENUM(NSInteger, OpenFileFunctionType) {
    FUNC_UNKNOWN,
    FUNC_STAT,
    FUNC_STAT64,
    FUNC_SYSCALL_STAT,
    FUNC_SYSCALL_STAT64,
    FUNC_SVC_0X80_STAT,
    FUNC_SVC_0X80_STAT64,
    FUNC_OPEN,
    FUNC_SYSCALL_OPEN,
    FUNC_SVC_0X80_OPEN,
    FUNC_FOPEN,
    FUNC_NSFILEMANAGER,
    FUNC_ACCESS,
    FUNC_FACCESSAT,
    FUNC_LSTAT,
    FUNC_REALPATH,
    FUNC_OPENDIR,
    FUNC___OPENDIR2,
    FUNC_NSURL,
};

typedef NS_ENUM(NSInteger, ButtonId) {
    BTN_STAT=1,
    BTN_STAT64=2,
    BTN_SYSCALL_STAT=3,
    BTN_SYSCALL_STAT64=4,
    BTN_SVC_0X80_STAT=5,
    BTN_SVC_0X80_STAT64=6,
    BTN_OPEN=7,
    BTN_SYSCALL_OPEN=8,
    BTN_SVC_0X80_OPEN=9,
    BTN_FOPEN=10,
    BTN_NSFILEMANAGER=11,
    BTN_ACCESS=12,
    BTN_FACCESSAT=13,
    BTN_LSTAT=14,
    BTN_REALPATH=15,
    BTN_OPENDIR=16,
    BTN___OPENDIR2=17,
    BTN_NSURL=18,
};

NS_ASSUME_NONNULL_BEGIN

@interface CrifanLibiOS : NSObject
// String List
//+ (NSArray *) strListToNSArray: (char*_Nullable*_Nullable)strList listCount:(int)listCount;
+ (NSArray *) strListToNSArray: (char**)strList listCount:(int)listCount;

// NSArray
+ (NSString*) nsStrListToStr: (NSArray*)curList;
+ (NSString*) nsStrListToStr: (NSArray*)curList isSortList:(BOOL)isSortList isAddIndexPrefix:(BOOL)isAddIndexPrefix;

// Open File
+ (BOOL) openFile:(NSString *)filePath funcType:(OpenFileFunctionType) funcType;

@end

NS_ASSUME_NONNULL_END
