/*
    File: CrifanLibiOS.m
    Function: crifan's common iOS function
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/CrifanLibiOS.m
    Updated: 20211203_1339
*/

#import "CrifanLibiOS.h"

const int OPEN_OK = 0;
const int OPEN_FAILED = -1;

const int OPEN_FD_INVALID = -1;

@implementation CrifanLibiOS

/*==============================================================================
 String List
==============================================================================*/

+ (NSArray *) strListToNSArray: (char**)strList listCount:(int)listCount
{
    NSMutableArray * nsArr = [NSMutableArray array];
    for(int i = 0; i < listCount; i++){
        char* curStr = strList[i];
        NSString* curNSStr = [NSString stringWithUTF8String: curStr];
        [nsArr addObject: curNSStr];
    }
    return nsArr;
}

/*==============================================================================
 NSArray
==============================================================================*/

+ (NSString*) nsStrListToStr: (NSArray*)curList isSortList:(BOOL)isSortList isAddIndexPrefix:(BOOL)isAddIndexPrefix {
    NSArray *outputList = curList;
    if(isSortList){
        outputList = [curList sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    }

    NSString *listStr = @"";
    unsigned long listCount = outputList.count;
//    for (NSString *curStr in curList) {
    for(int curIdx = 0; curIdx < listCount; curIdx++){
        if (curIdx > 0){
            listStr = [NSString stringWithFormat:@"%@\n", listStr];
        }

        if (isAddIndexPrefix){
            listStr = [NSString stringWithFormat:@"%@[%d] ", listStr, curIdx];
        }
        NSString* curStr = outputList[curIdx];
        listStr = [NSString stringWithFormat:@"%@%@", listStr, curStr];
    }
    listStr = [NSString stringWithFormat:@"列表总个数：%ld\n%@", listCount, listStr];
    NSLog(@"listStr=%@", listStr);
    return listStr;
}

+ (NSString*) nsStrListToStr: (NSArray*)curList{
    return [CrifanLibiOS nsStrListToStr:curList isSortList:FALSE isAddIndexPrefix:FALSE];
}

/*==============================================================================
 Open File
==============================================================================*/

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

__attribute__((always_inline)) int svc_0x80_stat_stat64(int syscall_number, const char * pathname, struct stat * stat_info) {
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
__attribute__((always_inline)) int svc_0x80_open(const char * pathname, int flags) {
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

@end
