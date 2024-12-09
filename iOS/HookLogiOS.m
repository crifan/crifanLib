/*
    File: HookLogiOS.m
    Function: crifan's common iOS hook log functions
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/HookLogiOS.m
    Updated: 20241207_1142
*/

#import "HookLogiOS.h"
#import "CrifanLibiOS.h"

/*==============================================================================
 Global Config
==============================================================================*/

// Note: os_log max length/limit is 1K=1024
// when split large NSString, for single line string length will use this definition
//    int LOG_MAX_LEN_ONCE = 1024;
//int LOG_MAX_LEN_ONCE = 1024 - 20;
//int LOG_MAX_LEN_ONCE = 1024 - 50;
//int LOG_MAX_LEN_ONCE = 1024 - 100;
//int LOG_MAX_LEN_ONCE = 1024 - 200;
int LOG_MAX_LEN_ONCE = 1024 - 150;


// output one log every N time
//long LOG_ONCE_PER_NUM = 10;
//long LOG_ONCE_PER_NUM = 20;
long LOG_ONCE_PER_NUM = 100;

/*==============================================================================
 Global Variable
==============================================================================*/

long gCurLogNum = 0;

//only for debug
long gNoUse = 0;


/*==============================================================================
 Log Utils
==============================================================================*/

bool nonEmptyHeader(id curHeaderDict){
    bool isNonEmpty = false;
    if (curHeaderDict != nil){
        id allKeys = [curHeaderDict allKeys];
        long int headerCount = [allKeys count];
        if (headerCount > 0) {
            isNonEmpty = true;
        }
    }
    return isNonEmpty;
}

// log for large (> 1024) string
void logLargeStr(NSString* largeStr){
//    NSMutableArray* splitedLineArr = splitToLines(largeStr, LOG_MAX_LEN_ONCE);
    NSMutableArray* splitedLineArr = [CrifanLibiOS splitToLines:largeStr maxLenPerLine:LOG_MAX_LEN_ONCE];
    for(int lineIdx = 0; lineIdx < splitedLineArr.count; lineIdx++){
        NSString* curLineStr = splitedLineArr[lineIdx];
//        os_log(OS_LOG_DEFAULT, "[%d] curLineStr=%@", lineIdx, curLineStr);
//        iosLogInfo("[%d] curLineStr=%{public}@", lineIdx, curLineStr);
        iosLogInfo("[%d] %{public}@", lineIdx, curLineStr);
    }
}

// log for possible large string
void logPossibleLargeStr(NSString* possibleLargeStr){
    if ([possibleLargeStr length] > LOG_MAX_LEN_ONCE){
//        iosLogInfo("%@", @"log_for_large_str:");
        logLargeStr(possibleLargeStr);
    } else {
//        iosLogInfo("%@", @"log_for_normal_str:");
        iosLogInfo("%{public}@", possibleLargeStr);
    }
}

void printCallStack(void){
    NSArray *callStackArr = [CrifanLibiOS printCallStack];
    iosLogInfo("callStackArr=%{public}@", callStackArr);
}

void printCallStack_largeStr(void){
    NSArray *callStackArr = [CrifanLibiOS printCallStack];
    NSString* callStackLargeStr = [NSString stringWithFormat:@"callStackArr=%@", callStackArr];
    logPossibleLargeStr(callStackLargeStr);
}

/*==============================================================================
 Debug Functions
==============================================================================*/

// write class description string into file
void dbgWriteClsDescToFile(char* className, id classObj){
    NSString* idNSStr = [classObj _ivarDescription];
    NSString* pdNSStr = [classObj _propertyDescription];
    NSString* mdNSStr = [classObj _methodDescription];
    NSString* smdNSStr = [classObj _shortMethodDescription];
    
    const char *idCStr = [idNSStr cStringUsingEncoding:NSUTF8StringEncoding];
    const char *pdCStr = [pdNSStr cStringUsingEncoding:NSUTF8StringEncoding];
    const char *mdCStr = [mdNSStr cStringUsingEncoding:NSUTF8StringEncoding];
    const char *smdCStr = [smdNSStr cStringUsingEncoding:NSUTF8StringEncoding];

    //    const char* smdOutputFile = "/var/root/dev/AADeviceInfo_shortMethodDescription.txt";
    //    const char* smdOutputFile = "/var/mobile/AADeviceInfo_shortMethodDescription.txt";
//    const char* outputFilePath = "/var/root/dev"; // failed for no write access
    const char* outputFilePath = "/var/mobile";
//    iosLogInfo("outputFilePath=%{public}s", outputFilePath);
//    const char* idOutputFile = "AADeviceInfo_ivarDescription.txt";
//    const char* pdOutputFile = "AADeviceInfo_propertyDescription.txt";
//    const char* mdOutputFile = "AADeviceInfo_methodDescription.txt";
//    const char* smdOutputFile = "AADeviceInfo_shortMethodDescription.txt";

    char idFullPath[200];
    char pdFullPath[200];
    char mdFullPath[200];
    char smdFullPath[200];

//    snprintf(idFullPath, sizeof(idFullPath), "%s/%s", outputFilePath, idOutputFile);
//    snprintf(pdFullPath, sizeof(pdFullPath), "%s/%s", outputFilePath, pdOutputFile);
//    snprintf(mdFullPath, sizeof(mdFullPath), "%s/%s", outputFilePath, mdOutputFile);
//    snprintf(smdFullPath, sizeof(smdFullPath), "%s/%s", outputFilePath, smdOutputFile);
    snprintf(idFullPath, sizeof(idFullPath), "%s/%s_ivarDescription.txt", outputFilePath, className);
    snprintf(pdFullPath, sizeof(pdFullPath), "%s/%s_propertyDescription.txt", outputFilePath, className);
    snprintf(mdFullPath, sizeof(mdFullPath), "%s/%s_methodDescription.txt", outputFilePath, className);
    snprintf(smdFullPath, sizeof(smdFullPath), "%s/%s_shortMethodDescription.txt", outputFilePath, className);

    writeStrToFile(idFullPath, (char*)idCStr);
    writeStrToFile(pdFullPath, (char*)pdCStr);
    writeStrToFile(mdFullPath, (char*)mdCStr);
    writeStrToFile(smdFullPath, (char*)smdCStr);

//    iosLogInfo("Written %s description into %s", className, outputFilePath);
}


@implementation HookLogiOS

@end
