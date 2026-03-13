/*
    File: CrifanLibiOS.m
    Function: crifan's common iOS function
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/CrifanLibiOS.m
    Updated: 20260313_1716
*/

#import "CrifanLibiOS.h"
#import "HookLogiOS.h"

@implementation CrifanLibiOS

/*==============================================================================
 String List
==============================================================================*/

// + (NSArray *) strListToNSArray: (char**)strList listCount:(int)listCount
+ (NSArray *) strListToNSArray: (const char *_Nonnull *_Nonnull)strList listCount:(int)listCount
{
    NSMutableArray * nsArr = [NSMutableArray array];
    if (strList) {
        for(int i = 0; i < listCount; i++){
            // char* curStr = strList[i];
            const char* curStr = strList[i];
            NSString* curNSStr = [NSString stringWithUTF8String: curStr];
            [nsArr addObject: curNSStr];
        }
    }
    return nsArr;
}

// Split large NSString into multiple line sub string array
//NSMutableArray* splitToLines(NSString* largeStr, int maxLenPerLine){
+(NSMutableArray*) splitToLines: (NSString*)largeStr maxLenPerLine:(int)maxLenPerLine {
    NSMutableArray *subNsstrList = [[NSMutableArray alloc] init];
    int nsstrLen = (int)[largeStr length];
//    os_log(OS_LOG_DEFAULT, "nsstrLen=%d", nsstrLen);
    if (nsstrLen > maxLenPerLine){
        int curCharIdx = 0;
        while( (curCharIdx + maxLenPerLine) < nsstrLen) {
            NSString* curSubNsstr = [largeStr substringWithRange:NSMakeRange(curCharIdx, maxLenPerLine)];
//            os_log(OS_LOG_DEFAULT, "curSubNsstr len=%lu", (unsigned long)[curSubNsstr length]);
            [subNsstrList addObject: curSubNsstr];
            curCharIdx += maxLenPerLine;
        }
        [subNsstrList addObject:[largeStr substringFromIndex: curCharIdx]];
    }
//    os_log(OS_LOG_DEFAULT, "largeStr=%@, maxLenPerLine=%d -> subNsstrList=%@", largeStr, maxLenPerLine, subNsstrList);
    return subNsstrList;
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
 Codesign
==============================================================================*/

// get embedded.mobileprovision path
// /private/var/containers/Bundle/Application/4366136E-242E-4C5D-9CC8-CF100A0B6FB2/ShowSysInfo.app/embedded.mobileprovision"
+ (NSString*) getEmbeddedCodesign {
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]; // embeddedPath    __NSCFString *    @"/private/var/containers/Bundle/Application/4366136E-242E-4C5D-9CC8-CF100A0B6FB2/ShowSysInfo.app/embedded.mobileprovision"    0x0000000282c11830
    return embeddedPath;
}

// is embedded.mobileprovision exist or not
+ (BOOL) isCodeSignExist {
    BOOL isExist = FALSE;
    NSString *embeddedPath = [CrifanLibiOS getEmbeddedCodesign];
    if ([[NSFileManager defaultManager] fileExistsAtPath:embeddedPath]) {
        isExist = TRUE;
    } else {
        isExist = FALSE;
    }
    
    return isExist;
}

// get application-identifier from embedded.mobileprovision
+ (NSString*) getAppId {
    NSString* appIdStr = NULL;
    if(![CrifanLibiOS isCodeSignExist]) {
        return NULL;
    }

    NSString *embeddedPath = [CrifanLibiOS getEmbeddedCodesign];
    if (NULL == embeddedPath) {
        return NULL;
    }

    // 注意：读取(application-identifier)描述文件的编码要使用: NSASCIIStringEncoding
    NSStringEncoding fileEncoding = NSASCIIStringEncoding;
//    NSStringEncoding fileEncoding = NSUTF8StringEncoding;
    NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:fileEncoding error:nil];
    NSArray<NSString *> *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    if (NULL == embeddedProvisioningLines) {
        return NULL;
    }

    for (int i = 0; i < embeddedProvisioningLines.count; i++) {
        if ([embeddedProvisioningLines[i] rangeOfString:@"application-identifier"].location != NSNotFound) {
            NSString *identifierString = embeddedProvisioningLines[i + 1];
            // <string>L2ZY2L7GYS.com.xx.xxx</string>
            // "\t\t<string>3WRHBBSBW4.*</string>"
            NSRange fromRange = [identifierString rangeOfString:@"<string>"];
            NSInteger fromPosition = fromRange.location + fromRange.length;
            NSInteger toPosition = [identifierString rangeOfString:@"</string>"].location;
            NSRange range;
            range.location = fromPosition;
            range.length = toPosition - fromPosition;
            NSString *fullIdentifier = [identifierString substringWithRange:range];
//            NSScanner *scanner = [NSScanner scannerWithString:fullIdentifier];
//            NSString *teamIdString;
//            [scanner scanUpToString:@"." intoString:&teamIdString];
//            NSRange teamIdRange = [fullIdentifier rangeOfString:teamIdString];
//            NSString *appIdentifier = [fullIdentifier substringFromIndex:teamIdRange.length + 1];
//            appIdStr = appIdentifier;
            
            appIdStr = fullIdentifier;
            break;
        }
    }

    return appIdStr;
}

// check app id is same with embedded.mobileprovision's application-identifier
+ (BOOL) isSelfAppId: (NSString*) selfAppId {
    BOOL isSelfId = FALSE;
    NSString* foundAddId = [CrifanLibiOS getAppId];
    // 对比签名teamID或者identifier信息
//   if (![foundAddId isEqualToString:identifier] || ![teamId isEqualToString:foundAddId]) {
    if ([foundAddId isEqualToString: selfAppId]) {
        isSelfId = TRUE;
    } else {
        isSelfId = FALSE;
//        // exit(0)
//        asm(
//            "mov X0,#0\n"
//            "mov w16,#1\n"
//            "svc #0x80"
//            );
    }

    return isSelfId;
}

/*==============================================================================
 Process
==============================================================================*/

// Get the running processes
// Note: refer: https://developer.apple.com/forums/thread/9440
//  for iOS 9.0+,  KERN_PROC_ALL not working
+ (NSArray *)runningProcesses {
    // Define the int array of the kernel's processes
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
//    size_t miblen = 4;
    int miblen = 4;
    
    // Make a new size and int of the sysctl calls
    size_t size = 0;
//    int st;
    int st = sysctl(mib, miblen, NULL, &size, NULL, 0);

    // Make new structs for the processes
    struct kinfo_proc * process = NULL;
    struct kinfo_proc * newprocess = NULL;
    
    // Do get all the processes while there are no errors
    do {
        // Add to the size
        size += (size / 10);
        // Get the new process
        newprocess = realloc(process, size);
        // If the process selected doesn't exist
        if (!newprocess){
            // But the process exists
            if (process){
                // Free the process
                free(process);
            }
            // Return that nothing happened
            return nil;
        }
        
        // Make the process equal
        process = newprocess;
        
        // Set the st to the next process
//        st = sysctl(mib, (int)miblen, process, &size, NULL, 0);
        st = sysctl(mib, miblen, process, &size, NULL, 0);
    } while (st == -1 && errno == ENOMEM);

    // As long as the process list is empty
    if (st == 0){
        // And the size of the processes is 0
        if (size % sizeof(struct kinfo_proc) == 0){
            // Define the new process
            int nprocess = (int)(size / sizeof(struct kinfo_proc));
            // If the process exists
            if (nprocess){
                // Create a new array
                NSMutableArray * array = [[NSMutableArray alloc] init];
                // Run through a for loop of the processes
                for (int i = nprocess - 1; i >= 0; i--){
                    // Get the process ID
                    NSString * processID = [[NSString alloc] initWithFormat:@"%d", process[i].kp_proc.p_pid];
                    // Get the process Name
                    NSString * processName = [[NSString alloc] initWithFormat:@"%s", process[i].kp_proc.p_comm];
                    // Get the process Priority
                    NSString *processPriority = [[NSString alloc] initWithFormat:@"%d", process[i].kp_proc.p_priority];
                    // Get the process running time
                    NSDate   *processStartDate = [NSDate dateWithTimeIntervalSince1970:process[i].kp_proc.p_un.__p_starttime.tv_sec];
                    // Create a new dictionary containing all the process ID's and Name's
                    NSDictionary *dict = [[NSDictionary alloc] initWithObjects:[NSArray arrayWithObjects:processID, processPriority, processName, processStartDate, nil]
                                                                       forKeys:[NSArray arrayWithObjects:@"ProcessID", @"ProcessPriority", @"ProcessName", @"ProcessStartDate", nil]];
                    
                    // Add the dictionary to the array
                    [array addObject:dict];
                }
                // Free the process array
                free(process);
                
                // Return the process array
                return array;
                
            }
        }
    }
    
    // Free the process array
    free(process);
    
    // If no processes are found, return nothing
    return nil;
}

// Print function call stack == backstrace
+ (NSArray *)printCallStack {
    NSArray *btArr = [NSThread callStackSymbols];
    return btArr;
}

@end

/*==============================================================================
 ObjC Runtime Utilities (C functions)
==============================================================================*/

// ---- IVAR helpers ----

ptrdiff_t getIvarOffset(Class cls, const char *ivarName) {
    Ivar ivar = class_getInstanceVariable(cls, ivarName);
    if (!ivar) {
        iosLogInfo("[CrifanLibiOS] [IVAR] WARNING: ivar '%s' not found on class %s",
                   ivarName, class_getName(cls));
        return -1;
    }
    return ivar_getOffset(ivar);
}

void writeBoolIvar(id instance, const char *ivarName, BOOL value) {
    Class cls = object_getClass(instance);
    ptrdiff_t offset = getIvarOffset(cls, ivarName);
    if (offset < 0) return;
    *(BOOL *)((uint8_t *)(__bridge void *)instance + offset) = value;
    iosLogInfo("[CrifanLibiOS] [IVAR] %s.%s = %d (offset %td)",
              class_getName(cls), ivarName, value, offset);
}

BOOL readBoolIvar(id instance, const char *ivarName) {
    Class cls = object_getClass(instance);
    ptrdiff_t offset = getIvarOffset(cls, ivarName);
    if (offset < 0) return NO;
    return *(BOOL *)((uint8_t *)(__bridge void *)instance + offset);
}

id readObjIvar(id instance, const char *ivarName) {
    Ivar ivar = class_getInstanceVariable(object_getClass(instance), ivarName);
    if (!ivar) return nil;
    return object_getIvar(instance, ivar);
}

void writeObjIvar(id instance, const char *ivarName, id value) {
    Ivar ivar = class_getInstanceVariable(object_getClass(instance), ivarName);
    if (!ivar) return;
    object_setIvar(instance, ivar, value);
    iosLogInfo("[CrifanLibiOS] [IVAR] %s.%s = %@ (object_setIvar)",
              class_getName(object_getClass(instance)), ivarName, value);
}

// ---- Class/Object introspection ----

void dumpClassMethods(const char *className) {
    Class cls = NSClassFromString([NSString stringWithUTF8String:className]);
    if (!cls) {
        iosLogInfo("[CrifanLibiOS] Class not found: %s", className);
        return;
    }
    
    iosLogInfo("[CrifanLibiOS] === Dump class: %s ===", className);
    
    // Class (+) methods
    unsigned int clsMethodCount = 0;
    Method *clsMethods = class_copyMethodList(object_getClass(cls), &clsMethodCount);
    iosLogInfo("[CrifanLibiOS] + methods (%u):", clsMethodCount);
    for (unsigned int i = 0; i < clsMethodCount; i++) {
        SEL sel = method_getName(clsMethods[i]);
        const char *enc = method_getTypeEncoding(clsMethods[i]);
        iosLogInfo("[CrifanLibiOS]   +[%s %s] enc=%s", className, sel_getName(sel), enc ? enc : "?");
    }
    if (clsMethods) free(clsMethods);
    
    // Instance (-) methods
    unsigned int instMethodCount = 0;
    Method *instMethods = class_copyMethodList(cls, &instMethodCount);
    iosLogInfo("[CrifanLibiOS] - methods (%u):", instMethodCount);
    for (unsigned int i = 0; i < instMethodCount; i++) {
        SEL sel = method_getName(instMethods[i]);
        const char *enc = method_getTypeEncoding(instMethods[i]);
        iosLogInfo("[CrifanLibiOS]   -[%s %s] enc=%s", className, sel_getName(sel), enc ? enc : "?");
    }
    if (instMethods) free(instMethods);
    
    // Properties
    unsigned int propCount = 0;
    objc_property_t *props = class_copyPropertyList(cls, &propCount);
    if (propCount > 0) {
        iosLogInfo("[CrifanLibiOS] Properties (%u):", propCount);
        for (unsigned int i = 0; i < propCount; i++) {
            const char *name = property_getName(props[i]);
            const char *attrs = property_getAttributes(props[i]);
            iosLogInfo("[CrifanLibiOS]   @property %s attrs=%s", name, attrs ? attrs : "?");
        }
    }
    if (props) free(props);
    
    iosLogInfo("[CrifanLibiOS] === End %s ===", className);
}

void dumpObjectProperties(id obj, const char *context) {
    if (!obj) return;
    
    Class cls = [obj class];
    unsigned int propCount = 0;
    objc_property_t *props = class_copyPropertyList(cls, &propCount);
    
    iosLogInfo("[CrifanLibiOS] %s: Dumping %u properties of <%s>", context, propCount, class_getName(cls));
    
    for (unsigned int i = 0; i < propCount; i++) {
        const char *propName = property_getName(props[i]);
        @try {
            id value = [obj valueForKey:[NSString stringWithUTF8String:propName]];
            iosLogInfo("[CrifanLibiOS]   %s.%s = %@", context, propName, value);
        } @catch (NSException *e) {
            // Property not KVC-compliant, skip
        }
    }
    
    if (props) free(props);
}

