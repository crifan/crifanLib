/*
    File: JbPathList.h
    Function: crifan's common iOS jailbreak list functions
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/JbPathList.h
    Updated: 20211210_1850
*/

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface JbPathList : NSObject

+ (NSArray *) jbPathList;
+ (BOOL) isJailbreakPath_iOS: (NSString*)curPath;

+ (NSArray *) jbDylibList;
+ (BOOL) isJbDylib: (NSString*)curPath;

@end

NS_ASSUME_NONNULL_END
