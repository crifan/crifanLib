//
//  JbPathList.m
//  ShowSysInfo
//
//  Created by crifan on 2021/11/8.
//

#import "JbPathList.h"
#import "JailbreakPathList.h"
#import "CrifanLibiOS.h"

@implementation JbPathList

+ (NSArray *) jbPathList
{
    const char** jailbreakPathList = getJailbreakPathList();

    NSMutableArray * jbPathArr = [NSMutableArray array];

//    //for debug
//    NSArray* additionalTestPathList = @[
//        // 20211112_0915 test abnormal path
//        @"/Library/dpkg",
//        @"/./Library/../Library/dpkg/",
//        @"/Applications/Cydia.app/../Cydia.app",
//        @"/Applications/Cydia.app/Info.plist",
////        @"/var/root/iOSOpenDevPackages/", // not jb file, just for test
//        @"/var/NotExisted",
//        // for EPERM = Operation not permitted
//        @"/./bin/../bin/./bash",
//        @"/private/./etc/ssh/../ssh/sshd_config",
//        @"/usr/././../usr/bin/ssh-keyscan",
//    ];
//
//    for (NSString* curAdditionalTestPach in additionalTestPathList){
//        [jbPathArr addObject: curAdditionalTestPach];
//    }

    jbPathArr = [CrifanLibiOS strListToNSArray:jailbreakPathList listCount:jailbreakPathListLen];

    return jbPathArr;
}

+ (BOOL) isJailbreakPath_iOS: (NSString*)curPath{
    BOOL isJb = FALSE;

    const char* curPathStr = [curPath UTF8String];

    isJb = isJailbreakPath(curPathStr);
    
    return isJb;
}

+ (NSArray *) jbDylibList
{
    return [CrifanLibiOS strListToNSArray:jailbreakPathList_Dylib listCount:jailbreakPathListLen_Dylib];
}

+ (BOOL) isJbDylib: (NSString*)curPath{
    BOOL isJbLib = FALSE;
    if([JbPathList.jbDylibList containsObject:curPath]){
        isJbLib = TRUE;
    }
    return isJbLib;
}

@end
