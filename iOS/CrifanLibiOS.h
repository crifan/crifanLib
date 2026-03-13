/*
    File: CrifanLibiOS.h
    Function: crifan's common iOS function
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/CrifanLibiOS.h
    Updated: 20260313_1724
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

/*==============================================================================
 ObjC Runtime Utilities (C functions)
 - IVAR read/write helpers for direct memory manipulation
 - Class/object introspection (dump methods, properties)
 - extern "C" to ensure correct linkage from Objective-C++ (.mm/.xm) files
==============================================================================*/

#ifdef __cplusplus
extern "C" {
#endif

// ---- IVAR helpers ----

// Get the byte offset of an instance variable; returns -1 if not found
ptrdiff_t getIvarOffset(Class _Nonnull cls, const char * _Nonnull ivarName);

// Read/write BOOL ivar by name
void writeBoolIvar(id _Nonnull instance, const char * _Nonnull ivarName, BOOL value);
BOOL readBoolIvar(id _Nonnull instance, const char * _Nonnull ivarName);

// Read/write object ivar by name (uses object_getIvar/object_setIvar)
id _Nullable readObjIvar(id _Nonnull instance, const char * _Nonnull ivarName);
void writeObjIvar(id _Nonnull instance, const char * _Nonnull ivarName, id _Nullable value);

// ---- Class/Object introspection ----

// Dump all class (+) and instance (-) methods and properties of a class (logs via iosLogInfo)
void dumpClassMethods(const char * _Nonnull className);

// Dump all KVC-accessible properties of an object instance (logs via iosLogInfo)
void dumpObjectProperties(id _Nonnull obj, const char * _Nonnull context);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
