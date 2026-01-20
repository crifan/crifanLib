/*
    File: CrifanLibiOS.h
    Function: crifan's common iOS function
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/CrifanLibiOS.h
    Updated: 20260120_1748
*/

#import <Foundation/Foundation.h>
#import <os/log.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>

#import "CrifanLib.h"

/*==============================================================================
 iOS Related
==============================================================================*/

NS_ASSUME_NONNULL_BEGIN

@interface CrifanLibiOS : NSObject

/*==============================================================================
 String List
==============================================================================*/

//+ (NSArray *) strListToNSArray: (char*_Nullable*_Nullable)strList listCount:(int)listCount;
// + (NSArray *) strListToNSArray: (char*_Nonnull*_Nonnull)strList listCount:(int)listCount;
+ (NSArray *) strListToNSArray: (const char *_Nonnull *_Nonnull)strList listCount:(int)listCount;

//NSMutableArray* splitToLines(NSString* largeStr, int maxLenPerLine);
+(NSMutableArray*) splitToLines: (NSString*)largeStr maxLenPerLine:(int)maxLenPerLine;

/*==============================================================================
 NSArray
==============================================================================*/

+ (NSString*) nsStrListToStr: (NSArray*)curList;
+ (NSString*) nsStrListToStr: (NSArray*)curList isSortList:(BOOL)isSortList isAddIndexPrefix:(BOOL)isAddIndexPrefix;

/*==============================================================================
 Codesign
==============================================================================*/

+ (BOOL) isCodeSignExist;
+ (NSString*) getEmbeddedCodesign;
+ (NSString*) getAppId;
+ (BOOL) isSelfAppId: (NSString*) selfAppId;

/*==============================================================================
 Process
==============================================================================*/

+ (NSArray *)runningProcesses;
+ (NSArray *)printCallStack;

@end

NS_ASSUME_NONNULL_END
