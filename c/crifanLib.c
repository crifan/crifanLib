/*
    File: CrifanLib.c
    Function: crifan's common C libs implementation
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/crifanLib.c
    Updated: 20211207_2241
*/

#include "CrifanLib.h"


/*==============================================================================
 Integer
==============================================================================*/

// 2, [1, 2, 3, 4], 4 -> true
bool isIntInList(int valueToCheck, int* intList, int intListLen){
    bool isInList = false;
    for(int i = 0; i < intListLen; i++){
        int curIntValue = intList[i];
        if (curIntValue == valueToCheck){
            isInList = true;
            break;
        }
    }

    return isInList;
}

/*==============================================================================
 String
==============================================================================*/

char* boolToStr(bool curBool){
    return curBool ? "True": "False";
}

// "CYDIA://xxx" -> "cydia://xxx"
char* strToLowercase(const char* origStr){
    char* lowerStr = strdup(origStr);
    char curChar = lowerStr[0];
    for(int i = 0; curChar != '\0'; i++){
        curChar = lowerStr[i];
        char curCharLower = tolower(curChar);
        lowerStr[i] = curCharLower;
    }
    return lowerStr;
}

bool strStartsWith(const char *fullStr, const char *prefixStr)
{
    bool isStartsWith = (0 == strncmp(prefixStr, fullStr, strlen(prefixStr)));
    return isStartsWith;
}

// "/Library/dpkg/", "/" -> true
bool strEndsWith(const char* fullStr, const char* endStr)
{
    if (!fullStr || !endStr){
        return false;
    }

    size_t fullStrLen = strlen(fullStr);
    size_t endStrLen = strlen(endStr);

    if (endStrLen >  fullStrLen){
        return false;
    }

//    return strncmp(fullStr + fullStrLen - endStrLen, endStr, endStrLen) == 0;
    const char* partStr = fullStr + (fullStrLen - endStrLen);
    bool isEndEqual = (0 == strcmp(partStr, endStr));
    return isEndEqual;
}

// "./relative/path", "./" -> "relative/path"
char* removeHead(const char* fullStr, const char* headStr){
    char *newStr = strdup(fullStr);

    size_t fullLen = strlen(fullStr);
    size_t headLen = strlen(headStr);

    if (headLen > fullLen){
        return newStr;
    }

    if (strStartsWith(fullStr, headStr)){
        newStr += headLen;
    }

    return newStr;
}

// "/./Library/../Library/dpkg/.", "/." -> "/./Library/../Library/dpkg"
char* removeTail(const char* fullStr, const char* tailStr){
    char *newStr = strdup(fullStr);
    
    size_t fullLen = strlen(fullStr);
    size_t tailLen = strlen(tailStr);

    if (tailLen > fullLen){
        return newStr;
    }

    if (strEndsWith(fullStr, tailStr)){
        size_t endIdx = fullLen - tailLen;
        newStr[endIdx] = '\0';
    }

    return newStr;
}

// "/./Library/../Library/dpkg/" -> "/./Library/../Library/dpkg"
char* removeEndSlash(const char* origPath)
{
    const char* slash = "/";
    char* newPath = NULL;

    bool isRoot = (0 == strcmp(origPath, slash));
    if (isRoot) {
        newPath = strdup(slash);
    }else{
        newPath = removeTail(origPath, slash);
    }

    return newPath;
}

// "/./Library/../Library/dpkg/./", "/./", "/" -> "/Library/../Library/dpkg"
char* strReplace(const char *fullStr, const char *replaceFromStr, const char *replaceToStr){
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    long len_from;  // length of from (the string to remove)
    long len_to; // length of with (the string to replace rep with)
    long len_front; // distance between from and end of last from
    int count;    // number of replacements

    // sanity checks and initialization
    if (!fullStr || !replaceFromStr){
        return NULL;
    }

    len_from = strlen(replaceFromStr);
    if (len_from == 0){
        return NULL; // empty rep causes infinite loop during count
    }

    if (!replaceToStr){
        replaceToStr = "";
    }

    len_to = strlen(replaceToStr);

    // count the number of replacements needed
    ins = (char *)fullStr;
    for (count = 0; (tmp = strstr(ins, replaceFromStr)); ++count) {
        ins = tmp + len_from;
    }
    
    long newStrLen = strlen(fullStr) + (len_to - len_from) * count + 1;
    tmp = result = malloc(newStrLen);

    if (!result){
        return NULL;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(fullStr, replaceFromStr);
        len_front = ins - fullStr;
        tmp = strncpy(tmp, fullStr, len_front) + len_front;
        tmp = strcpy(tmp, replaceToStr) + len_to;
        fullStr += len_front + len_from; // move to next "end of rep"
    }
    strcpy(tmp, fullStr);
    return result;
}

/*
 input:
    fullStr="/bin/bash/.."
    delim="/"
 output:
    *resultListLenPtr = 3
    *resultSubStrListPtr = [
        "bin",
        "bash"
        "..",
    ]
 */
void strSplit(const char* fullStr, const char* delim, char*** resultSubStrListPtr, int* resultListLenPtr){
//    printf("fullStr=%s, delim=%s\n", fullStr, delim);

    const int ListLenMaxEnought = 100;
    char** tempSubStrListPtr = malloc(ListLenMaxEnought * sizeof(char*));

    char *token;
    int curListIdx = 0;
    int curListLen = 0;
    
    char *inputFullStr = strdup(fullStr);

    /* get the first token */
    token = strtok(inputFullStr, delim);

    /* walk through other tokens */
    while( token != NULL ) {
        char* tmpToken = strdup(token);
//        printf("[%d] %s\n", curListIdx, tmpToken);

        tempSubStrListPtr[curListIdx] = tmpToken;

        curListLen = curListIdx + 1;

        curListIdx += 1;

        token = strtok(NULL, delim);
    }

    free(inputFullStr);

//    printf("curListLen=%d\n", curListLen);

    if (curListLen > 0){
        *resultListLenPtr = curListLen;
        *resultSubStrListPtr = tempSubStrListPtr;
  
//        // for debug
//        printf("%s =>\n", fullStr);
//        for(int i=0; i < curListLen; i++){
//            char* curSubStr = tempSubStrListPtr[i];
//            printf("\t[%d] %s\n", i, curSubStr);
//        }
    } else {
        *resultListLenPtr = 0;
        *resultSubStrListPtr = NULL;
    }
}


/*==============================================================================
 File Size
==============================================================================*/

//http://www.crifan.com/order_how_to_calculate_the_file_size__length_caculate_the_file_length__size/
//calculate file size/length
//return negative if error

//method 1: use fgetc
//good: universial
//bad: maybe overflow if files too large
long calulateFilesize_fgetc(char* inputFilename){
    long filesize = 0;
    
    FILE * inputFp = fopen(inputFilename, "rb");

    if (!inputFp) {
        //printf("Error opening input file %s", inputFilename);
        return -1;
    }

    /* caculate the file length(bytes) */
    char singleChar = fgetc(inputFp);
    while(EOF != singleChar)
    {
        ++filesize;
        singleChar = fgetc(inputFp);
    }
    
    return filesize;
}

//method 2: fseek + ftell
//good: fast
//bad:
long calulateFilesize_ftell(char* inputFilename){
    long filesize = 0;
    
    FILE* inputFp = fopen(inputFilename, "rb");

    if (!inputFp) {
        //printf("Error opening input file %s", inputFilename);
        return -1;
    }

    /*
        标识符     数值     代表的起始点
        SEEK_SET   0        文件开始
        SEEK_END   2        文件末尾
        SEEK_CUR   1        文件当前位置
    */

    fseek(inputFp, 0, SEEK_END);

    filesize = ftell(inputFp);
    
    return filesize;
}

//method 3: fstat
//good: fast
//bad: system dependent
long calulateFilesize_fstat(char* inputFilename)
{
    long filesize = 0;
    //http://linux.die.net/man/2/fstat
    struct stat fileStat;
    
    //http://www.go4expert.com/articles/understanding-linux-fstat-example-t27449/
    int inputFd = open(inputFilename, O_RDONLY); // fd=File Descriptor
    if (inputFd < 0) {
        //open file error
        return inputFd;
    }

    int fstatRet = fstat(inputFd, &fileStat);
    if (fstatRet < 0)
    {
        close(inputFd);
        
        return fstatRet;
    }

    filesize = fileStat.st_size;
    
    close(inputFd);
    
    return filesize;
}

/*==============================================================================
 File Mode
==============================================================================*/

// file mode to string
// st_mode=16877 -> modeStrBuf="rwxr-xr-x"
void fileModeToStr(mode_t mode, char * modeStrBuf) {
    // buf must have at least 10 bytes
    const char chars[] = "rwxrwxrwx";
    for (size_t i = 0; i < 9; i++) {
//        buf[i] = (mode & (1 << (8-i))) ? chars[i] : '-';
        bool hasSetCurBit = mode & (1 << (8-i));
        modeStrBuf[i] = hasSetCurBit ? chars[i] : '-';
    }
    modeStrBuf[9] = '\0';
}

//void fileTypeToStr(mode_t mode, char * fileStrBuf) {
//char* fileTypeToStr(mode_t mode) {
char* fileTypeToChar(mode_t mode) {
    char * fileStrBuf = NULL;
    char* unknown = "?";
    fileStrBuf = strdup(unknown);

    bool isFifo = (bool)S_ISFIFO(mode);
    if (isFifo){
        fileStrBuf = strdup("p");
    }

    bool isChar = (bool)S_ISCHR(mode);
    if (isChar){
        fileStrBuf = strdup("c");
    }

    bool isDir = (bool)S_ISDIR(mode);
    if (isDir){
        fileStrBuf = strdup("d");
    }

    bool isBlock = (bool)S_ISBLK(mode);
    if (isBlock){
        fileStrBuf = strdup("b");
    }

    bool isRegular = (bool)S_ISREG(mode);
    if (isRegular){
        fileStrBuf = strdup("-");
    }

    bool isLink = (bool)S_ISLNK(mode);
    if (isLink){
        fileStrBuf = strdup("l");
    }

    bool isSocket = (bool)S_ISSOCK(mode);
    if (isSocket){
        fileStrBuf = strdup("s");
    }

////    if (strcmp(fileStrBuf, "") != 0){
//    if (strlen(fileStrBuf) > 0){
//        // remove first empty char
//        char firstChar = fileStrBuf[0];
//        if (firstChar == ' '){
//            fileStrBuf = fileStrBuf + 1;
//        }
//
//        // remove last ','
//        int curLen = (int)strlen(fileStrBuf);
//        int lastCharIdx = curLen - 1;
//        char lastChar = fileStrBuf[lastCharIdx];
//        if (lastChar == ','){
//            fileStrBuf[lastCharIdx] = '\0';
//        }
//    }

    return fileStrBuf;
}

char* fileSizeToStr(off_t fileStSize){
    char* fileSizeStr = NULL;
    asprintf(&fileSizeStr, "%lld", (long long)fileStSize);
    return fileSizeStr;
}

char* statToStr(struct stat* statInfo){
//    char fileTypeStr[100];
    char *fileTypeStr=NULL;
//    fileTypeToStr(statInfo->st_mode, fileTypeStr);
//    fileTypeStr = fileTypeToStr(statInfo->st_mode);
    fileTypeStr = fileTypeToChar(statInfo->st_mode);
    //fileTypeStr    char *    "d"    0x0000000282331e00

    char fileModeStr[10];
    fileModeToStr(statInfo->st_mode, fileModeStr);
    //fileModeStr    char [10]    "rwxr-xr-x"
  
    char *fullFileModeStr=NULL;
    asprintf(&fullFileModeStr, "%s%s", fileTypeStr, fileModeStr);
    //fullFileModeStr    char *    "drwxr-xr-x"    0x0000000282331d80
    
    char* fileSizeStr = fileSizeToStr(statInfo->st_size);

//    char *statStr;
//    unsigned long MaxBufNum = 100;
//    snprintf(statStr, MaxBufNum, "st_mode: st_mode=%s", stModeStr);
    
//    int maxEnoughtBufLen = 50;
////    char statStr[maxEnoughtBufLen];
//    char *statStr = (char*)malloc(maxEnoughtBufLen * sizeof(char));
//    sprintf(statStr, "stat info: st_mode=%s", stModeStr);

    char *statStr = NULL;
    asprintf(&statStr, "stat info: st_mode=%s, st_size=%s", fullFileModeStr, fileSizeStr);
    //statStr    char *    "stat info: st_mode=-rwxr-xr-x, st_size=3221225472"    0x00000002808c7180

    //TODO: parse more field to human readble info
    //    statInfo->st_atimespec
    //    statInfo->st_birthtimespec
    //    statInfo->st_blksize
    //    statInfo->st_blocks
    //    statInfo->st_ctimespec
    //    statInfo->st_dev
    //    statInfo->st_flags
    //    statInfo->st_gen
    //    statInfo->st_gid
    //    statInfo->st_ino
    //    statInfo->st_lspare
    //    statInfo->st_mode
    //    statInfo->st_mtimespec
    //    statInfo->st_nlink
    //    statInfo->st_qspare
    //    statInfo->st_rdev
    //    statInfo->st_size
    //    statInfo->st_uid

    return statStr;
}

/*==============================================================================
 File Path
==============================================================================*/

// remove "xxx/.." part
// "/usr/../usr/bin/ssh-keyscan" -> "/usr/bin/ssh-keyscan"
char* removeTwoDotPart(const char* origPath){
    const char *slash = "/";
//    const char *slashTwoDot = "/..";
    const char *twoDot = "..";

    char* newPath = NULL;
    char* toFreeStr = NULL;

    char* foundTwoDotPtr = strstr(origPath, twoDot);
    if(NULL == foundTwoDotPtr){
        // not found, return origin path
        newPath = strdup(origPath);
        return newPath;
    }

    bool isParseOk = true;

    char** subStrList = NULL;
    int subStrLen = 0;
    strSplit(origPath, slash, &subStrList, &subStrLen);
    if ((NULL != subStrList) && (subStrLen > 0)){
//        printf("%s, %s -> %d\n", origPath, slash, subStrLen);

//        bool shouldOmit = FALSE;
//        for(int i= subStrLen - 1; i >= 0; i--){
//            char* curSubStr = subStrList[i];
//            printf("[%d] %s\n", i, curSubStr);
//        }
        newPath = strdup("");
        int curIdx = subStrLen - 1;
        while(curIdx >= 0){
            char* curSubStr = subStrList[curIdx];
//            printf("[%d] %s\n", curIdx, curSubStr);
            bool isTwoDot = (0 == strcmp(twoDot, curSubStr));
            if(isTwoDot) {
                free(curSubStr);
//                printf("Omit  current: [%d] ..\n", curIdx);

                // omit current
                curIdx -= 1;
                
                if (curIdx >= 0){
//                    char* prevSubStr = subStrList[curIdx];
//                    printf("Omit previous: [%d] %s\n", curIdx, prevSubStr);

                    // omit next(previous)
                    curIdx -= 1;
                } else {
                    isParseOk = false;
                    printf("! Invalid case: [%d] '..' previous is None for %s\n", curIdx + 1, origPath);
                    // TODO: for most safe, need free reaming sub string
                    break;
                }
            } else {
                toFreeStr = newPath;
                asprintf(&newPath, "%s/%s", curSubStr, newPath);
                free(toFreeStr);
                free(curSubStr);

                curIdx -= 1;
            }

//            printf("now: newPath=%s\n", newPath);
        }
        
        if (isParseOk){
            if (strStartsWith(origPath, slash)){
                if(!strStartsWith(newPath, slash)){
                    toFreeStr = newPath;
                    asprintf(&newPath, "/%s", newPath);
                    free(toFreeStr);
                }
            }

            toFreeStr = newPath;
            newPath = removeEndSlash(newPath);
            free(toFreeStr);
        }
    } else {
        printf("! Failed to split path %s\n", origPath);
        isParseOk = false;
    }

    if(!isParseOk){
        toFreeStr = newPath;
        // restore origin path
        newPath = strdup(origPath);
        free(toFreeStr);
    }

    return newPath;
}

// "/Library/dpkg/", "/Library/dpkg" -> true
// "/./Library/../Library/dpkg/", "/Library/dpkg" -> true
bool isPathEaqual(const char* path1, const char* path2){
    bool isEqual = false;

    char* purePath1 = toPurePath(path1);
    char* purePath2 = toPurePath(path2);

    // check tail include '/' or not
    char* purePath1NoEndSlash = removeEndSlash(purePath1);
    char* purePath2NoEndSlash = removeEndSlash(purePath2);

    free(purePath1);
    free(purePath2);

    isEqual = (0 == strcmp(purePath1NoEndSlash, purePath2NoEndSlash));

    free(purePath1NoEndSlash);
    free(purePath2NoEndSlash);

    return  isEqual;
}

/* use realpath() to parse out realpath
    remove '.' and 'xxx/.'
    do soft link parese to real path
*/
bool parseRealPath(const char* curPath, char* gotRealPath){
    bool isParseOk = false;

    char realPath[PATH_MAX];
    char *returnPtr = realpath(curPath, realPath);
    if (returnPtr == NULL){
        char *errMsg = strerror(errno);
        printf("errMsg=%s", errMsg);
//        os_log(OS_LOG_DEFAULT, "parseRealPath: realpath open %{public}s failed: errno=%d, errMsg=%{public}s", curPath, errno, errMsg);

        if (EPERM == errno) {
            // hook_stat: realpath open /usr/bin/scp failed: errno=1, errMsg=Operation not permitted
//            os_log(OS_LOG_DEFAULT, "parseRealPath: when EPERM, realPath=%{public}s", realPath);
//            if (realPath != NULL){
//                os_log(OS_LOG_DEFAULT, "parseRealPath: path: input=%{public}s -> real=%{public}s", curPath, realPath);
//            } else {
//                os_log(OS_LOG_DEFAULT, "parseRealPath: open %{public}s error EPERM, but can not get real path", curPath);
//                return OPEN_FAILED;
//            }
            // Note: here realPath must not NULL, so no need to check

            isParseOk = true;
        } else {
            // TODO: add other errno support if necessary
//            return OPEN_FAILED;

            isParseOk = false;
        }
    } else {
//        os_log(OS_LOG_DEFAULT, "parseRealPath: realpath resolve ok, path: input=%{public}s -> real=%{public}s", curPath, realPath);
        isParseOk = true;
    }

    if (isParseOk){
        strcpy(gotRealPath, realPath);
//        os_log(OS_LOG_DEFAULT, "parseRealPath: gotRealPath=%{public}s, realPath=%{public}s", gotRealPath, realPath);
    }

    return isParseOk;
}

/*
 Process path to pure path
    for '.' = dot = current folder: remove it
    for '..' = two dot = parent folder: remove 'xxx/..' part

 Note: here not do full realpath work, such as resolve soft link to real path

 Example:
    /./usr/././../usr/bin/./ssh-keyscan -> /usr/bin/ssh-keyscan
    /bin/bash/.. -> /bin
    usr/local/bin/.. -> usr/local
    /./bin/../bin/./bash -> /bin/bash
    /private/./etc/ssh/../ssh/sshd_config -> /private/etc/ssh/sshd_config
    ./relative/path -> relative/path
    /Library/dpkg/./ -> /Library/dpkg
    /Library/dpkg/. -> /Library/dpkg
    /./Library/../Library/./dpkg/. -> /Library/dpkg
    /Applications/Cydia.app/../Cydia.app -> /Applications/Cydia.app
*/
char* toPurePath(const char* origPath){
//    printf("origPath=%s\n", origPath);

    const char *dot = ".";
    const char *slash = "/";
    const char *dotSlash = "./";
    const char *slashDot = "/.";
    const char *slashDotSlash = "/./";

//    const char *slashTwoDot = "/..";

    char* toFreeStr = NULL;
    char* purePath = "";

//    if(0 == strcmp("", origPath)){
//        return "";
//    }

    // if not contain '.', ignore
    char *foundDotPtr = strstr(origPath, dot);
    if (NULL != foundDotPtr){
        purePath = strdup(origPath);

        // 1. remove ./ or .

        // 1.1 start with ./ -> remove it
        toFreeStr = purePath;
        purePath = removeTail(purePath, dotSlash);
    //    printf("\tRemoved tail '%s' -> %s\n", dotSlash, purePath);
        // "./relative/path" -> "relative/path"
        free(toFreeStr);

        // 1.2 end with /. -> remove it
        toFreeStr = purePath;
        purePath = removeTail(purePath, slashDot);
    //    printf("\tRemoved tail '%s' -> %s\n", slashDot, purePath);
        // "/./Library/../Library/dpkg/." -> "/./Library/../Library/dpkg"
        free(toFreeStr);

        // 1.3 end with /./ -> remove it
        toFreeStr = purePath;
        purePath = removeTail(purePath, slashDotSlash);
    //    printf("\tRemoved tail '%s' -> %s\n", slashDotSlash, purePath);
        // "/./Library/../Library/dpkg/./" -> "/./Library/../Library/dpkg"
        free(toFreeStr);

        // 1.4 replce "/./" to "/"
        char *foundSlashPointSlash = NULL;
        while((foundSlashPointSlash = strstr(purePath, slashDotSlash))){
            toFreeStr = purePath;
            purePath = strReplace(purePath, slashDotSlash, slash);
            free(toFreeStr);
        }
    //    printf("\tReplaced '%s' to '%s' -> %s\n", slashDotSlash, slash, purePath);
        // "/./usr/././../usr/bin/./ssh-keyscan" -> "/usr/../usr/bin/ssh-keyscan"

        // 1.5 remove head "./"
        toFreeStr = purePath;
        purePath = removeHead(purePath, dotSlash);
    //    printf("\tRemoved head '%s' -> %s\n", dotSlash, purePath);
        // "./relative/path" -> "relative/path"
        free(toFreeStr);

        // 2. remove xxx/../ or xxx/..
        
        // 2.1 (only) remove "/.."
        toFreeStr = purePath;
        purePath = removeTwoDotPart(purePath);
    //    printf("\tRemoved two dot part 'xxx/..' -> %s\n", purePath);
        // "/usr/../usr/bin/ssh-keyscan" -> "/usr/bin/ssh-keyscan"
        free(toFreeStr);
    } else {
        purePath = strdup(origPath);
    }

    // 3. remove end "/"
    toFreeStr = purePath;
    purePath = removeEndSlash(purePath);
//    printf("\tRemoved end slash '/' -> %s\n", purePath);
    // "/usr/bin/ssh-keyscan/" -> "/usr/bin/ssh-keyscan"
    free(toFreeStr);

//    printf("\torigPath=%s =>> purePath=%s\n", origPath, purePath);
    return purePath;
}
