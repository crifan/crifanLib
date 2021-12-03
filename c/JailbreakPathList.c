/*
    File: JailbreakPathList.c
    Function: crifan's common jailbreak file path list
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/JailbreakPathList.c
    Updated: 20211126_1913
*/

#include "JailbreakPathList.h"

/*==============================================================================
 Jailbreak Path List
==============================================================================*/

// when use isJailbreakPath_realpath, should disable KEEP_SOFT_LINK
// when use isJailbreakPath_pureC, shold enable KEEP_SOFT_LINK
#define KEEP_SOFT_LINK

const char* jailbreakPathList_Dylib[] = {
    // common: tweak plugin libs
    "/Library/MobileSubstrate/DynamicLibraries/0Shadow.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dSupport.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/dygz.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/MobileSafety.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/xCon.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zorro.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zzzzHeiBaoLib.dylib",

    "/usr/lib/libsubstrate.dylib",

    // Cydia Substrate libs
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/lib/substrate/SubstrateInserter.dylib",
    "/usr/lib/substrate/SubstrateLoader.dylib",
    "/usr/lib/substrate/SubstrateBootstrap.dylib",

    // Substitute libs
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substitute-inserter.dylib",
    "/usr/lib/substitute-loader.dylib",

    // Other libs
    "/private/var/lib/clutch/overdrive.dylib",
    "/usr/lib/libapt-inst.2.0.dylib",
    "/usr/lib/libapt-private.0.0.0.dylib",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/tweakloader.dylib",
};

const char* jailbreakPathList_Other[] = {
    "/Applications/Activator.app",
    "/Applications/ALS.app",
    "/Applications/blackra1n.app",
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Filza.app",
    "/Applications/FlyJB.app",
    "/Applications/Icy.app",
    "/Applications/iFile.app",
    "/Applications/Iny.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MTerminal.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/Snoop-itConfig.app",
    "/Applications/WinterBoard.app",

    "/bin/sh",
    "/bin/bash",

    "/etc/apt",
    "/etc/clutch.conf",
    "/etc/clutch_cracked.plist",
    "/etc/ssh/sshd_config",

    "/Library/Activator",
    "/Library/Flipswitch",
    "/Library/dpkg/",

    "/Library/Frameworks/CydiaSubstrate.framework/",
#ifdef KEEP_SOFT_LINK
    "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", // -> /usr/lib/libsubstrate.dylib
#endif
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/"
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/CydiaSubstrate.h",
    "/Library/Frameworks/CydiaSubstrate.framework/Info.plist",
#ifdef KEEP_SOFT_LINK
    "/Library/Frameworks/CydiaSubstrate.framework/SubstrateLoader.dylib", // -> /usr/lib/substitute-loader.dylib
#endif

    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/Library/LaunchDaemons/com.rpetrich.rocketbootstrapd.plist",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/com.tigisoftware.filza.helper.plist",
    "/Library/LaunchDaemons/dhpdaemon.plist",
    "/Library/LaunchDaemons/re.frida.server.plist",

    "/Library/MobileSubstrate/",
    "/Library/MobileSubstrate/DynamicLibraries/",

    "/Library/MobileSubstrate/DynamicLibraries/afc2dService.plist",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dSupport.plist",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.plist",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.plist",
    "/Library/MobileSubstrate/DynamicLibraries/dygz.plist",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/MobileSafety.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/DynamicLibraries/xCon.plist",
    "/Library/MobileSubstrate/DynamicLibraries/zorro.plist",
    "/Library/MobileSubstrate/DynamicLibraries/zzzzHeiBaoLib.plist",

    "/private/etc/apt",
    "/private/etc/apt/preferences.d/checkra1n",
    "/private/etc/apt/preferences.d/cydia",
    "/private/etc/dpkg/origins/debian",
    "/private/etc/ssh/sshd_config",

    "/private/var/cache/apt/",
    "/private/var/cache/clutch.plist",
    "/private/var/cache/clutch_cracked.plist",
    "/private/var/db/stash",
    "/private/var/evasi0n",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia/",
    "/private/var/lib/dpkg/",
    
    "/private/var/mobile/Applications/", //TODO: non-jailbreak can normally open?
    "/private/var/mobile/Library/Filza/",
    "/private/var/mobile/Library/Filza/pasteboard.plist",
    "/private/var/mobile/Library/Cydia/",
    "/private/var/mobile/Library/SBSettingsThemes/",
    "/private/var/root/Documents/Cracked/",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",

    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",

#ifdef KEEP_SOFT_LINK
    // Note: /User -> /var/mobile/
    "/User/Applications/", //TODO: non-jailbreak can normally open?
    "/User/Library/Filza/",
    "/User/Library/Filza/pasteboard.plist",
    "/User/Library/Cydia/",
#endif

    "/usr/bin/cycc",
    "/usr/bin/cycript",
    "/usr/bin/cynject",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/ssh",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-agent",
    "/usr/bin/ssh-keygen",
    "/usr/bin/ssh-keyscan",
    "/usr/bin/sshd",
    
    "/usr/include/substrate.h",

    "/usr/lib/cycript0.9/",
    "/usr/lib/cycript0.9/com/",
    "/usr/lib/cycript0.9/com/saurik/"
    "/usr/lib/cycript0.9/com/saurik/substrate/",
    "/usr/lib/cycript0.9/com/saurik/substrate/MS.cy",

#ifdef KEEP_SOFT_LINK
    "/usr/lib/libsubstitute.0.dylib", // -> /usr/lib/libsubstrate.dylib
#endif
    "/usr/lib/substrate/",

    "/usr/lib/TweakInject",

    "/usr/libexec/cydia/",
    "/usr/libexec/sftp-server",
    "/usr/libexec/substrate",
    "/usr/libexec/substrated",
    "/usr/libexec/ssh-keysign",

    "/usr/local/bin/cycript",

    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",

#ifdef KEEP_SOFT_LINK
    // /var -> /private/var/
    "/var/mobile/Applications/", //TODO: non-jailbreak can normally open?
    "/var/mobile/Library/Filza/",
    "/var/mobile/Library/Filza/pasteboard.plist",
    "/var/mobile/Library/Cydia/",
#endif
};

const int jailbreakPathListLen_Dylib = sizeof(jailbreakPathList_Dylib)/sizeof(const char *);
const int jailbreakPathListLen_Other = sizeof(jailbreakPathList_Other)/sizeof(const char *);

const int jailbreakPathListLen = jailbreakPathListLen_Dylib + jailbreakPathListLen_Other;

//int jailbreakPathListLen = sizeof(jailbreakPathList)/sizeof(const char *);

const char** getJailbreakPathList(void){
    int strPtrMaxIdx = jailbreakPathListLen;
    int strPtrNum = strPtrMaxIdx + 1;
    const char** jailbreakPathStrPtrList = malloc(sizeof(const char *) * strPtrNum);
    // set each string
    for(int curStrIdx = 0; curStrIdx < jailbreakPathListLen_Dylib; curStrIdx++){
        const char* curStrPtr = jailbreakPathList_Dylib[curStrIdx];
        jailbreakPathStrPtrList[curStrIdx] = curStrPtr;
    }

    for(int curStrIdx = jailbreakPathListLen_Dylib; curStrIdx < strPtrNum; curStrIdx++){
        int otherStrPtrIdx = curStrIdx - jailbreakPathListLen_Dylib;
        const char* curStrPtr = jailbreakPathList_Other[otherStrPtrIdx];
        jailbreakPathStrPtrList[curStrIdx] = curStrPtr;
    }
    // set end
    jailbreakPathStrPtrList[strPtrMaxIdx] = NULL;

    return jailbreakPathStrPtrList;
}


/*==============================================================================
 Jailbreak Function
==============================================================================*/

bool isJailbreakPath_pureC(const char *curPath){
    bool isJbPath = false;
    char* purePath = toPurePath(curPath);
    char* matchedJsPath = NULL;

    const char** jailbreakPathList = getJailbreakPathList();
    for (int i=0; i < jailbreakPathListLen; i++) {
        const char* curJbPath = jailbreakPathList[i];
        if (isPathEaqual(purePath, curJbPath)){
            isJbPath = true;
            matchedJsPath = (char *)curJbPath;
            break;
        }

        // check sub folder
        // "/Applications/Cydia.app/Info.plist" belong to "/Applications/Cydia.app/", should bypass
        // but avoid: '/usr/bin/ssh-keyscan' starts with '/usr/bin/ssh'
        char* curJbPathNoEndSlash = removeEndSlash(curJbPath);
        char * curJbPathWithEndSlash = NULL;
        asprintf(&curJbPathWithEndSlash, "%s/", curJbPathNoEndSlash);

        if (strStartsWith(purePath, curJbPathWithEndSlash)){
            isJbPath = true;
            matchedJsPath = (char *)curJbPath;
            break;
        }
    }
    
//    //for deubg
//    if(isJbPath){
//        printf("matchedJsPath=%s\n", matchedJsPath);
//    }
    
    return isJbPath;
}

bool isJailbreakPath_realpath(const char *pathname){
    bool isJbPath = false;

    char gotRealPath[PATH_MAX];
    bool isParseRealPathOk = parseRealPath(pathname, gotRealPath);
//    os_log(OS_LOG_DEFAULT, "isJailbreakPath: isParseRealPathOk=%{bool}d", isParseRealPathOk);

    char curRealPath[PATH_MAX];
    if (isParseRealPathOk) {
        strcpy(curRealPath, gotRealPath);
    } else {
        strcpy(curRealPath, pathname);
    }
//    os_log(OS_LOG_DEFAULT, "isJailbreakPath: curRealPath=%{public}s", curRealPath);

    char* realPathNoEndSlash = removeEndSlash(curRealPath);
//    os_log(OS_LOG_DEFAULT, "isJailbreakPath: realPathNoEndSlash=%{public}s", realPathNoEndSlash);

    int charPtrLen = sizeof(const char *);
//    os_log(OS_LOG_DEFAULT, "isJailbreakPath: charPtrLen=%d", charPtrLen);
    printf("charPtrLen=%d", charPtrLen);
//    int charPtrListLen = sizeof((char *[])jailbreakPathList);
//    os_log(OS_LOG_DEFAULT, "isJailbreakPath: jailbreakPathListLen=%d", jailbreakPathListLen);

    const char** jailbreakPathList = getJailbreakPathList();
    for (int i=0; i < jailbreakPathListLen; i++) {
        const char* curJbPath = jailbreakPathList[i];
        char* curJbPathNoEndSlash = removeEndSlash(curJbPath);
//        os_log(OS_LOG_DEFAULT, "isJailbreakPath: curJbPath=%{public}s -> curJbPathNoEndSlash=%{public}s", curJbPath, curJbPathNoEndSlash);

        if(0 == strcmp(realPathNoEndSlash, curJbPathNoEndSlash)){
//            os_log(OS_LOG_DEFAULT, "isJailbreakPath: found same path: pathname=%{public}s, realPathNoEndSlash=%{public}s, curJbPath=%{public}s, curJbPathNoEndSlash=%{public}s", pathname, realPathNoEndSlash, curJbPath, curJbPathNoEndSlash);
//            return OPEN_FAILED;
            isJbPath = true;
        } else {
            // check sub folder
            // "/Applications/Cydia.app/Info.plist" belong to "/Applications/Cydia.app/", should bypass
//            if (strStartsWith(realPathNoEndSlash, curJbPathNoEndSlash)){
            // to avoid: '/usr/bin/ssh-keyscan' starts with '/usr/bin/ssh'
            char * curJbPathWithEndSlash = NULL;
            asprintf(&curJbPathWithEndSlash, "%s/", curJbPathNoEndSlash);
            if (strStartsWith(realPathNoEndSlash, curJbPathWithEndSlash)){
//                os_log(OS_LOG_DEFAULT, "isJailbreakPath: not same path, but realPathNoEndSlash=%{public}s starts with curJbPathWithEndSlash=%{public}s", realPathNoEndSlash, curJbPathWithEndSlash);
//                return OPEN_FAILED;
                isJbPath = true;
            }
        }
    }

    return isJbPath;
}

bool isJailbreakPath(const char *pathname){
//    return isJailbreakPath_realpath(pathname);
    return isJailbreakPath_pureC(pathname);
}
