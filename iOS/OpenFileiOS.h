/*
    File: OpenFileiOS.h
    Function: crifan's common iOS open file functions header
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/openFileiOS.h
    Updated: 20230327_1111
*/

#import <Foundation/Foundation.h>
#import <dirent.h>
#import <fcntl.h>
#import <sys/types.h>
#import <sys/param.h>
#import <sys/mount.h>

NS_ASSUME_NONNULL_BEGIN

/*==============================================================================
 Exported Global Variable
==============================================================================*/

extern const int OPEN_OK;
extern const int OPEN_FAILED;

extern const int OPEN_FD_INVALID;

extern const int ACCESS_OK;
extern const int ACCESS_FAILED;

extern const int STAT_OK;
extern const int STAT_FAILED;

extern const int STATFS_OK;
extern const int STATFS_FAILED;

extern const int FORK_FAILED;

extern const int PTRACE_OK;
extern const int PTRACE_FAILED;

extern const int FOPEN_OPEN_FAILED;

extern const int FCNTL_FAILED;

//extern const char* REALPATH_FAILED;
extern char* REALPATH_FAILED;

//extern const char* OPENDIR_FAILED;
//extern char* OPENDIR_FAILED;
//extern const int OPENDIR_FAILED;
//extern int OPENDIR_FAILED;
extern DIR* OPENDIR_FAILED;

extern const int StrPointerSize;

extern const int DLADDR_FAILED;

extern const int DYLD_IMAGE_INDEX_INVALID;
extern const long DYLD_IMAGE_SLIDE_INVALID;

extern const int SYSCTL_OK;
extern const int SYSCTL_FAIL;


/*==============================================================================
 Global Type
==============================================================================*/

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
    FUNC_STATFS,
    FUNC_STATFS64,
    FUNC_FSTATFS,
    FUNC_FSTATAT,
    FUNC_FSTAT,
    FUNC_SYSCALL_LSTAT,
    FUNC_SYSCALL_FSTAT,
    FUNC_SYSCALL_FSTATAT,
    FUNC_SYSCALL_STATFS,
    FUNC_SYSCALL_FSTATFS,
    FUNC_SYSCALL_FOPEN,
    FUNC_SYSCALL_ACCESS,
    FUNC_SYSCALL_FACCESSAT,
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
    BTN_STATFS=19,
    BTN_STATFS64=20,
    BTN_FSTATFS=21,
    BTN_FSTATAT=22,
    BTN_FSTAT=23,
    BTN_SYSCALL_LSTAT=24,
    BTN_SYSCALL_FSTAT=25,
    BTN_SYSCALL_FSTATAT=26,
    BTN_SYSCALL_STATFS=27,
    BTN_SYSCALL_FSTATFS=28,
    BTN_SYSCALL_FOPEN=29,
    BTN_SYSCALL_ACCESS=30,
    BTN_SYSCALL_FACCESSAT=31,
};


/*==============================================================================
 Define
==============================================================================*/



/*==============================================================================
 Const
==============================================================================*/

const int OPEN_OK = 0;
const int OPEN_FAILED = -1;

const int OPEN_FD_INVALID = -1;

const int ACCESS_OK = 0;
const int ACCESS_FAILED = -1;

const int STAT_OK = 0;
const int STAT_FAILED = -1;

const int STATFS_OK = 0;
const int STATFS_FAILED = -1;

const int FORK_FAILED = -1;

const int PTRACE_OK = 0;
const int PTRACE_FAILED = -1;

const int FOPEN_OPEN_FAILED = NULL;

const int FCNTL_FAILED = -1;

//const char* _Nullable REALPATH_FAILED = NULL;
char* _Nullable REALPATH_FAILED = NULL;

//int OPENDIR_FAILED = NULL;
//const int OPENDIR_FAILED = NULL;
//const char* _Nullable OPENDIR_FAILED = NULL;
//char* _Nullable OPENDIR_FAILED = NULL;
//const DIR* _Nullable OPENDIR_FAILED = NULL;
DIR* OPENDIR_FAILED = NULL;

const int StrPointerSize = sizeof(const char *);

const int DLADDR_FAILED = 0;

const int DYLD_IMAGE_INDEX_INVALID = -1;
const long DYLD_IMAGE_SLIDE_INVALID = 0;

const int SYSCTL_OK = 0;
const int SYSCTL_FAIL = -1;

@interface OpenFileiOS : NSObject

/*==============================================================================
 Open File
==============================================================================*/

+ (BOOL) openFile:(NSString *)filePath funcType:(OpenFileFunctionType) funcType;

@end

NS_ASSUME_NONNULL_END
