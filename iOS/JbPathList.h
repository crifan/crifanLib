//
//  JbPathList.h
//  ShowSysInfo
//
//  Created by crifan on 2021/11/8.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface JbPathList : NSObject

+ (NSArray *) jbPathList;
+ (BOOL) isJailbreakPath_iOS: (NSString*)curPath;

+ (NSArray *) jbDylibList;
+ (BOOL) isJbDylib: (NSString*)curPath;

@end

NS_ASSUME_NONNULL_END
