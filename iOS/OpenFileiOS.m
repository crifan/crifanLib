/*
    File: OpenFileiOS.m
    Function: crifan's common iOS open file functions
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/openFileiOS.m
    Updated: 20230327_1111
*/

#import "OpenFileiOS.h"
#import "CrifanLibiOS.h"

@implementation OpenFileiOS

//#define asm_set_syscall_number(SYSCALL_NUMBER) "mov x16, #SYSCALL_NUMBER\n"
//
//#define asm_svc_0x80_stat64() \
//    "mov x0, %[pathname_p]\n" \
//    "mov x1, %[stat_info_p]\n" \
//    asm_set_syscall_number(SYS_stat64) \
//    "svc #0x80\n" \
//    "mov %[ret_p], x0\n"

//                     "mov x16, #338\n" \

//__attribute__((always_inline)) long svc_0x80_stat_stat64(int syscall_number, const char * pathname, struct stat * stat_info) {
//        long ret = 0;
//        long long_syscall_number = syscall_number;
//        __asm__ volatile(
//             "mov x0, %[pathname_p]\n"
//             "mov x1, %[stat_info_p]\n"
//             "mov x16, %[long_syscall_number_p]\n"
//             "svc #0x80\n"
//             "mov %[ret_p], x0\n"
//            : [ret_p]"=r"(ret)
//            : [long_syscall_number_p]"r"(long_syscall_number), [pathname_p]"r"(pathname), [stat_info_p]"r"(stat_info)
//             : "x0", "x1", "x16"
//        );
//        return ret == 0 ? ret : -1;
//}

__attribute__((always_inline)) static int svc_0x80_stat_stat64(int syscall_number, const char * pathname, struct stat * stat_info) {
    register const char * x0_pathname asm ("x0") = pathname; // first arg
    register struct stat * x1_stat_info asm ("x1") = stat_info;  // second arg
    register int x16_syscall_number asm ("x16") = syscall_number; // special syscall number store to x16
    register int x4_ret asm("x4") = OPEN_FAILED; // store result
    __asm__ volatile(
         "svc #0x80\n"
         "mov x4, x0\n"
        : "=r"(x4_ret)
        : "r"(x0_pathname), "r"(x1_stat_info), "r"(x16_syscall_number)
//         : "x0", "x1", "x4", "x16"
    );
    return x4_ret;
}

//__attribute__((always_inline)) int svc_0x80_open(const char * pathname, int flags, mode_t mode) {
__attribute__((always_inline)) static int svc_0x80_open(const char * pathname, int flags) {
    register const char * x0_pathname asm ("x0") = pathname; // first arg
    register int x1_flags asm ("x1") = flags;  // second arg
//    register unsigned int x2_mode asm ("x2") = (unsigned int)mode;  // third arg
    register int x16_syscall_number asm ("x16") = SYS_open; // special syscall number store to x16
    register int x4_ret asm("x4") = OPEN_FD_INVALID; // store result
    __asm__ volatile(
//         "mov x16, #5\n" // SYS_open
         "svc #0x80\n"
         "mov x4, x0\n"
        : "=r"(x4_ret)
        : "r"(x0_pathname), "r"(x1_flags), "r"(x16_syscall_number)
// : "r"(x0_pathname), "r"(x1_flags), "r"(x2_mode), "r"(x16_syscall_number)
//         : "x16"
//         : "x0", "x1", "x5", "x16"
    );
    return x4_ret;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

+ (BOOL) openFile:(NSString *)filePath funcType:(OpenFileFunctionType) funcType{
    int MODE_NONE = 0;

    BOOL isOpenOk = FALSE;
    struct stat stat_info;
//    int openResult = stat(filePath, &stat_info);
//    int openResult = stat((char *)filePath, &stat_info);
    const char * filePathStr = [filePath UTF8String];

    int openResult = OPEN_FAILED;
    int retFd = OPEN_FAILED;
    BOOL isUseStatInfo = FALSE;
    BOOL isUseFd = FALSE;

    if (FUNC_STAT == funcType){
        isUseStatInfo = TRUE;
        openResult = stat(filePathStr, &stat_info);
    } else if (FUNC_STAT64 == funcType) {
//        struct stat64 stat_info; // Variable has incomplete type 'struct stat64'
//        const char * filePathStr = [filePath UTF8String];
//        int openResult = stat64(filePathStr, &stat_info);
    } else if (FUNC_SYSCALL_STAT == funcType) {
        isUseStatInfo = TRUE;
        //Note: for open normal file, return 0 is OK, but st_mode is abnormal !
        openResult = syscall(SYS_stat, filePathStr, &stat_info);
    } else if (FUNC_SYSCALL_STAT64 == funcType){
        isUseStatInfo = TRUE;
        openResult = syscall(SYS_stat64, filePathStr, &stat_info);
    } else if (FUNC_SYSCALL_LSTAT == funcType){
        isUseStatInfo = TRUE;
        openResult = syscall(SYS_lstat, filePathStr, &stat_info);
    } else if (FUNC_SYSCALL_FSTAT == funcType){
        isUseStatInfo = TRUE;

        int curFd = open(filePathStr, O_RDONLY);
        if (curFd > 0){
            openResult = syscall(SYS_fstat, curFd, &stat_info);
        } else {
            isOpenOk = FALSE;
        }
    } else if (FUNC_SYSCALL_FSTATAT == funcType){
        // NOTE: syscall(SYS_fstatat) not work until 20220316 -> awalys return -1

        // int fstatat(int fd, const char* pathname, struct stat* buf, int flags);
        isUseStatInfo = TRUE;

//        int curFd = open(filePathStr, O_RDONLY);
//        if (curFd > 0){
//            openResult = syscall(SYS_fstatat, curFd, filePathStr, &stat_info, F_DUPFD);
//        } else {
//            isOpenOk = FALSE;
//        }

//        int notUsedDirfd = -1;
//        openResult = syscall(SYS_fstatat, notUsedDirfd, filePathStr, &stat_info, F_DUPFD);
//        openResult = syscall(SYS_fstatat, notUsedDirfd, filePathStr, &stat_info, 0);
        openResult = syscall(SYS_fstatat, AT_FDCWD, filePathStr, &stat_info, 0);
    } else if (FUNC_SYSCALL_STATFS == funcType){
        isUseStatInfo = TRUE;
        // int statfs(const char *path, struct statfs *buf);
        openResult = syscall(SYS_statfs, filePathStr, &stat_info);
    } else if (FUNC_SYSCALL_FSTATFS == funcType){
        isUseStatInfo = TRUE;
        // int fstatfs(int fd, struct statfs *buf);
        int curFd = open(filePathStr, O_RDONLY);
        if (curFd > 0){
            openResult = syscall(SYS_fstatfs, curFd, &stat_info);
        } else {
            isOpenOk = FALSE;
        }
    } else if (FUNC_SVC_0X80_STAT == funcType) {
        isUseStatInfo = TRUE;
        //Note: for open normal file, return 0 is OK, but st_mode is abnormal !
        openResult = svc_0x80_stat_stat64(SYS_stat, filePathStr, &stat_info);
    } else if (FUNC_SVC_0X80_STAT64 == funcType) {
        isUseStatInfo = TRUE;
        openResult = svc_0x80_stat_stat64(SYS_stat64, filePathStr, &stat_info);
    } else if (FUNC_OPEN == funcType) {
        isUseFd = TRUE;
        retFd = open(filePathStr, O_RDONLY);
    } else if (FUNC_SYSCALL_OPEN == funcType){
        isUseFd = TRUE;
//        retFd = syscall(SYS_open, filePathStr, O_RDONLY);
        retFd = syscall(SYS_open, filePathStr, O_RDONLY, MODE_NONE);
    } else if (FUNC_SYSCALL_FOPEN == funcType){
        // no SYS_fopen
    } else if (FUNC_SVC_0X80_OPEN == funcType) {
        isUseFd = TRUE;
//        retFd = svc_0x80_open(filePathStr, O_RDONLY, MODE_NONE);
        retFd = svc_0x80_open(filePathStr, O_RDONLY);
    } else if (FUNC_FOPEN == funcType) {
        FILE* fp = fopen(filePathStr, "r");
        if (fp != NULL){
            isOpenOk = TRUE;
            NSLog(@"fopen %@ -> fp=%p", filePath, fp);
        } else{
            isOpenOk = FALSE;
            NSLog(@"failed fopen %@", filePath);
            
            // log print erro info
            NSLog(@"errno=%d\n", errno);
            char *errMsg = strerror(errno);
            NSLog(@"errMsg=%s\n", errMsg);
        }
    } else if (FUNC_NSFILEMANAGER == funcType) {
        NSFileManager *defaultManager = [NSFileManager defaultManager];
        NSString* filePathNsStr = [NSString stringWithFormat:@"%s", filePathStr];

        BOOL isExisted = [defaultManager fileExistsAtPath: filePathNsStr];
        NSLog(@"isExisted=%s", boolToStr(isExisted));

        BOOL isDir = FALSE;
        BOOL isExistedWithDir = [defaultManager fileExistsAtPath:filePathNsStr isDirectory: &isDir];
        NSLog(@"isExistedWithDir=%s, isDir=%s", boolToStr(isExistedWithDir), boolToStr(isDir));

        isOpenOk = isExisted || isExistedWithDir;

        NSString* curResultStr = @"";

        if(isExisted){
            curResultStr = [NSString stringWithFormat:@"%@ 是否是目录：%@", @"路径存在", isDir ? @"是":@"否"];
        } else{
            curResultStr = [NSString stringWithFormat:@"%@", @"路径不存在"];
        }

        NSLog(@"fileExistsAtPath %@ -> %@", filePathNsStr, curResultStr);
        
    } else if (FUNC_NSURL == funcType) {
        NSString* fileStr = [NSString stringWithUTF8String:filePathStr];
        NSString* fileWithFilePrefix = [NSString stringWithFormat:@"file://%@", fileStr];
        NSURL* fileUrl = [NSURL URLWithString:fileWithFilePrefix];
        NSError* error = NULL;
        BOOL isReachable = [fileUrl checkResourceIsReachableAndReturnError:&error];
        NSLog(@"isReachable=%s, error=%@", boolToStr(isReachable), (error != NULL) ? error : @"");

        // for debug
        if (isReachable){
            NSLog(@"fileStr=%@", fileStr);
        }

        isOpenOk = isReachable;
        NSLog(@"NSURL checkResourceIsReachableAndReturnError %@ -> %s", fileStr, boolToStr(isReachable));
    } else if (FUNC_ACCESS == funcType) {
        int retValue = access(filePathStr, F_OK);
        NSLog(@"access %s -> %d", filePathStr, retValue);

        if (retValue != ACCESS_OK){
            isOpenOk = FALSE;
        } else {
            isOpenOk = TRUE;
        }
    } else if (FUNC_SYSCALL_ACCESS == funcType) {
        int retValue = syscall(SYS_access, filePathStr, F_OK);
        NSLog(@"SYS_access %s -> %d", filePathStr, retValue);
        if (retValue != ACCESS_OK){
            isOpenOk = FALSE;
        } else {
            isOpenOk = TRUE;
        }
    } else if (FUNC_FSTATAT == funcType) {
        isOpenOk = FALSE;

        int tmpFd = open(filePathStr, O_RDONLY);

        if (tmpFd > 0){
            isOpenOk = TRUE;

            struct stat statInfo;
            memset(&statInfo, 0, sizeof(struct stat));
            int fstatatRet = fstatat(tmpFd, filePathStr, &statInfo, F_DUPFD);
            if (STATFS_OK == fstatatRet) {
                isOpenOk = TRUE;
            } else {
                isOpenOk = FALSE;
            }
        } else {
            // when fd < 0, normally is -1, means open file failed
            isOpenOk = FALSE;
            NSLog(@"open() failed for %@", filePath);
        }
    } else if (FUNC_FACCESSAT == funcType) {
        int curDirFd = 0;
        int retValue = ACCESS_FAILED;

//        // 1. test relative path
////        const char* curDir = "/private/var/mobile/Library/Filza/";
////        const char* curFile = "scripts/README.url";
//
////        const char* curDir = "/private/var/mobile/Library/";
////        const char* curFile = "Filza/scripts/README.url";
////        const char* curDir = "/private/./var/../var/mobile/Library/./";
////        const char* curFile = "Filza/./scripts/../scripts/README.url";
//        const char* curDir = "/usr/lib";
//        const char* curFile = "libsubstrate.dylib";
//
//        curDirFd = open(curDir, O_RDONLY);
//        NSLog(@"curDir=%s -> curDirFd=%d", curDir, curDirFd);
//
////        // for debug: get file path from fd
////        char filePath[PATH_MAX];
////        int fcntlRet = fcntl(curDirFd, F_GETPATH, filePath);
////        const int FCNTL_FAILED = -1;
////        if (fcntlRet != FCNTL_FAILED){
////            NSLog(@"fcntl OK: curDirFd=%d -> filePath=%s", curDirFd, filePath);
////        } else {
////            NSLog(@"fcntl fail for curDirFd=%d", curDirFd);
////        }
//
//        retValue = faccessat(curDirFd, curFile, F_OK, AT_EACCESS);
//        NSLog(@"faccessat curDir=%s,curFile=%s -> %d", curDir, curFile, retValue);

        // 2. test input path
        const int FAKE_FD = 0;
        curDirFd = FAKE_FD;
        retValue = faccessat(curDirFd, filePathStr, F_OK, AT_EACCESS);
        NSLog(@"faccessat curDirFd=%d, filePathStr=%s -> %d", curDirFd, filePathStr, retValue);

        if (retValue != ACCESS_FAILED){
            isOpenOk = TRUE;
        } else {
            isOpenOk = FALSE;
        }
    } else if (FUNC_SYSCALL_FACCESSAT == funcType) {
        // NOTE: syscall(SYS_faccessat) not work until 20220317 -> awalys return -1

        int curDirFd = 0;
        int retValue = ACCESS_FAILED;

        const int FAKE_FD = 0;
        curDirFd = FAKE_FD;
//        retValue = syscall(SYS_faccessat, curDirFd, filePathStr, F_OK, AT_EACCESS);
        retValue = syscall(SYS_faccessat, curDirFd, filePathStr, F_OK, 0);
        if (retValue != ACCESS_FAILED){
            isOpenOk = TRUE;
        } else {
            isOpenOk = FALSE;
        }
    } else if (FUNC_LSTAT == funcType) {
        isOpenOk = FALSE;
        bool isLink = FALSE;

        struct stat statInfo;
        int lstatRet = lstat(filePathStr, &statInfo);
        if (STAT_OK == lstatRet){
//            isLink = statInfo.st_mode & S_IFLNK;
            isLink = S_ISLNK(statInfo.st_mode);
            if (isLink) {
                isOpenOk = TRUE;
            }
        }

        NSLog(@"lstat filePathStr=%s -> isLink=%s -> isOpenOk=%s", filePathStr, boolToStr(isLink), boolToStr(isOpenOk));
    } else if (FUNC_STATFS == funcType) {
        isOpenOk = FALSE;
        struct statfs statfsInfo;
        int statfsRet = statfs(filePathStr, &statfsInfo);
        if (STATFS_OK == statfsRet) {
            isOpenOk = TRUE;
        } else {
            isOpenOk = FALSE;
        }
        NSLog(@"statfs filePathStr=%s -> isOpenOk=%s", filePathStr, boolToStr(isOpenOk));
    } else if (FUNC_STATFS64 == funcType) {
        isOpenOk = FALSE;
        // NOTE: iOS not support struct statfs64 -> only macOS support struct statfs64
//        struct statfs64 statfs64Info; // Variable has incomplete type 'struct statfs64'
//        int statfs64Ret = statfs64(filePathStr, &statfs64Info); // Implicit declaration of function 'statfs64' is invalid in C99
    } else if (FUNC_FSTATFS == funcType) {
        isOpenOk = FALSE;
        int tmpFd = open(filePathStr, O_RDONLY);

        if (tmpFd > 0){
            isOpenOk = TRUE;

            struct statfs statfsInfo;
            memset(&statfsInfo, 0, sizeof(struct statfs));
            int fstatfsRet = fstatfs(tmpFd, &statfsInfo);
            if (STATFS_OK == fstatfsRet) {
                isOpenOk = TRUE;
            } else {
                isOpenOk = FALSE;
            }
        } else {
            // when fd < 0, normally is -1, means open file failed
            isOpenOk = FALSE;
            NSLog(@"open() failed for %@", filePath);
        }
    } else if (FUNC_FSTAT == funcType) {
        isOpenOk = FALSE;
        int tmpFd = open(filePathStr, O_RDONLY);

        if (tmpFd > 0){
            isOpenOk = TRUE;

            struct stat statInfo;
            memset(&statInfo, 0, sizeof(struct stat));
            int fstatRet = fstat(tmpFd, &statInfo);
            if (STAT_OK == fstatRet) {
                isOpenOk = TRUE;
            } else {
                isOpenOk = FALSE;
            }
        } else {
            // when fd < 0, normally is -1, means open file failed
            isOpenOk = FALSE;
            NSLog(@"open() failed for %@", filePath);
        }
    } else if (FUNC_REALPATH == funcType) {
        char parsedRealPath[PATH_MAX];
        char *resolvedPtr = realpath(filePathStr, parsedRealPath);
        if (NULL != resolvedPtr){
            NSLog(@"realpath OK: filePathStr=%s -> parsedRealPath=%s", filePathStr, parsedRealPath);
            isOpenOk = TRUE;
        } else {
            NSLog(@"realpath fail for filePathStr=%s", filePathStr);
            isOpenOk = FALSE;
        }
        NSLog(@"realpath filePathStr=%s -> isOpenOk=%s", filePathStr, boolToStr(isOpenOk));
    } else if (FUNC_OPENDIR == funcType) {
        DIR* retDir = opendir(filePathStr);
        if (NULL != retDir){
            NSLog(@"opendir OK: filePathStr=%s -> retDir=%p", filePathStr, retDir);
            NSLog(@"\tDIR: __dd_fd=%d,__dd_loc=%ld,__dd_size=%ld,__dd_buf=%s,__dd_len=%d,__dd_seek=%ld,__padding=%ld,__dd_flags=%d",
                retDir->__dd_fd, retDir->__dd_loc, retDir->__dd_size, retDir->__dd_buf, retDir->__dd_len, retDir->__dd_seek, retDir->__padding, retDir->__dd_flags);
            isOpenOk = TRUE;
        } else {
            NSLog(@"opendir fail for filePathStr=%s", filePathStr);
            isOpenOk = FALSE;
        }

        NSLog(@"opendir filePathStr=%s -> retDir=%p -> isOpenOk=%s", filePathStr, retDir, boolToStr(isOpenOk));
    } else if (FUNC___OPENDIR2 == funcType) {
        DIR* retDir = __opendir2(filePathStr, DTF_HIDEW|DTF_NODUP);
        if (NULL != retDir){
            NSLog(@"__opendir2 OK: filePathStr=%s -> retDir=%p", filePathStr, retDir);
            NSLog(@"\tDIR: __dd_fd=%d,__dd_loc=%ld,__dd_size=%ld,__dd_buf=%s,__dd_len=%d,__dd_seek=%ld,__padding=%ld,__dd_flags=%d",
                retDir->__dd_fd, retDir->__dd_loc, retDir->__dd_size, retDir->__dd_buf, retDir->__dd_len, retDir->__dd_seek, retDir->__padding, retDir->__dd_flags);
            isOpenOk = TRUE;
        } else {
            NSLog(@"__opendir2 fail for filePathStr=%s", filePathStr);
            isOpenOk = FALSE;
        }

        NSLog(@"__opendir2 filePathStr=%s -> retDir=%p -> isOpenOk=%s", filePathStr, retDir, boolToStr(isOpenOk));
    }

    if (isUseStatInfo){
        NSLog(@"stat info open %@ -> openResult=%d", filePath, openResult);

        if (OPEN_OK == openResult){
            isOpenOk = TRUE;

            char * statStr = statToStr(&stat_info);
            NSLog(@"stat_info=%s", statStr);
            free(statStr);
        } else {
            // Note: when stat return < 0, stat is not valid, seems random value
            isOpenOk = FALSE;
        }
    }

    if (isUseFd){
        NSLog(@"open() %@ -> return fd=%d", filePath, retFd);
        if (retFd > 0){
            isOpenOk = TRUE;
        } else {
            // when fd < 0, normally is -1, means open file failed
            isOpenOk = FALSE;

            // log print erro info
            NSLog(@"errno=%d\n", errno);
            char *errMsg = strerror(errno);
            NSLog(@"errMsg=%s\n", errMsg);
        }
    }

    NSLog(@"Open path %@ result %s", filePath, boolToStr(isOpenOk));
//    os_log(@"Open path %@ is %{bool}d", filePath, isOpenOk);

    return isOpenOk;
}
#pragma clang diagnostic pop

@end
