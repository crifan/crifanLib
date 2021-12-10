/*
    File: CrifanLibDemo.c
    Function: crifan's common C lib function demo implementation
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/CrifanLibDemo.c
    Updated: 20211208_1058
*/

//#include <stdio.h>
#include <sys/time.h>
#include "CrifanLibDemo.h"
#include "CrifanLib.h"
#include "JailbreakPathList.h"

/**************************************************************************************************
 Test isIntInList
****************************************************************************************************/
void testIsIntInList(void){
    int testIntValue = 2;
    int intList[] = {1, 2, 3, 4};
    bool isInList = isIntInList(testIntValue, intList, 4);
    printf("isInList=%d", isInList);
}

/**************************************************************************************************
 to pure path
****************************************************************************************************/
//for debug: to pure path
void testParsePurePath(void){
    // for debug: parse to pure path via pure C
    const char* specialPathList[] = {
        "./relative/path",
        "/Library/dpkg/./",
        "/Library/dpkg/",
        "/Library/dpkg/.",
        "/./Library/../Library/./dpkg/.",
        "/Applications/Cydia.app/../Cydia.app",
        "/bin/bash",
        "/./usr/././../usr/bin/./ssh-keyscan",
        "/bin/bash/..",
        "../bin/./bash/././..",
        "../bin/bash/..",
        "usr/local/bin/..",
        "/./bin/../bin/./bash",
        "/private/./etc/ssh/../ssh/sshd_config",
    };
    int specialPathListLen = sizeof(specialPathList)/sizeof(const char *);
    for (int i=0; i < specialPathListLen; i++) {
        const char* curSpeicalPath = specialPathList[i];
        char* curRealPath = toPurePath(curSpeicalPath);
        printf("orig: %s -> real: %s\n", curSpeicalPath, curRealPath);
    }
}

/**************************************************************************************************
 path equal
****************************************************************************************************/

//for debug
void testPathCompare(void){
    char* path1 = "/Library/dpkg";
    char* path2 = "/Library/dpkg/";
    bool isEqual = isPathEaqual(path1, path2);
    printf("isEqual=%s\n", boolToStr(isEqual));

    char* path3 = "/./Library/./../Library/./dpkg";
//    char* path3 = ".././Library/./../Library/./dpkg";
    char* path4 = "/Library/dpkg/";
    bool isEqual2 = isPathEaqual(path3, path4);
    printf("isEqual2=%s\n", boolToStr(isEqual2));
}

/**************************************************************************************************
 jailbreak path
****************************************************************************************************/

//for debug: detect jb path
void testJbPathDetect(void){
    const char* jsPathList[] = {
        "/usr/bin/ssh",
        "/usr/bin/ssh-",
        "/Applications/Cydia.app/Info.plist",
        "/bin/bash",
        "/Applications/Cydia.app/../Cydia.app",
        "/./usr/././../usr/bin/./ssh-keyscan",
        "/./bin/../bin/./bash",
        "/private/./etc/ssh/../ssh/sshd_config",
    };
    int jbPathListLen = sizeof(jsPathList)/sizeof(const char *);
    for (int i=0; i < jbPathListLen; i++) {
        const char* curJbPath = jsPathList[i];
        bool isJbPath = isJailbreakPath(curJbPath);
        printf("curJbPath=%s -> isJbPath=%s\n", curJbPath, boolToStr(isJbPath));
        printf("\n");
    }
}

/**************************************************************************************************
 string lowercase
****************************************************************************************************/

void testLowcase(void){
    char* str1 = "CYDIA://xxx";
    char* str2 = "Cydia://xxx";
    char* startWithLower = "cydia://";
    
    char* lowerStr1 = strToLowercase(str1);
    bool isEqual1 = strStartsWith(lowerStr1, startWithLower);
    printf("isEqual1=%s\n", boolToStr(isEqual1));
    free(lowerStr1);
    
    char* lowerStr2 = strToLowercase(str2);
    bool isEqual2 = strStartsWith(lowerStr2, startWithLower);
    printf("isEqual2=%s\n", boolToStr(isEqual2));
    free(lowerStr2);
}

/**************************************************************************************************/
/* Time */
/**************************************************************************************************/

/* use for only test several times in a loop */
#define MAX_TEST_COUNT              15

// How to calculate the elapsed time
//http://www.crifan.com/how_to_calculate_the_elapsed_time/
void showCalculateElapsedTime(void){
    struct timeval  tv_begin_mdct, tv_end_mdct;
    int test_count = 0; // test times
    // every part of encoder time of one frame in milliseconds
    long mdct_time = 0;

    //calculate mdct time of one of the firt ten frames
    if(test_count <= MAX_TEST_COUNT)
    {
        gettimeofday(&tv_begin_mdct, 0);
    }

    // ......
    // do what you wan to do 
    // ......
    //Func();

    //calculate mdct time of one of the firt ten frames
    if( test_count <= MAX_TEST_COUNT )
    {
        gettimeofday(&tv_end_mdct, 0);
        mdct_time = tv_end_mdct.tv_usec - tv_begin_mdct.tv_usec;
        printf("The mdct time of the %d frame is ttt%ld msn", test_count, mdct_time/1000);
    }
}

