/*
	File: FridaAndroidUtil.js
	Function: crifan's common Frida Android Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/FridaAndroidUtil.js
	Updated: 20241121
*/

// Frida Android Util
class FridaAndroidUtil {

  // android common root related binary files
  // static RootBinFileList = ["/system/bin/su", "/system/xbin/su", "/system/bin/magisk"]
  static RootBinFileList = [
    "/su",
    "/su/bin/su",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/system/bin/magisk",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/system/bin/cufsdosck",
    "/system/xbin/cufsdosck",
    "/system/bin/cufsmgr",
    "/system/xbin/cufsmgr",
    "/system/bin/cufaevdd",
    "/system/xbin/cufaevdd",
    "/system/bin/conbb",
    "/system/xbin/conbb",
  ]

  // {env: {clazz: className} }
  static cacheDictEnvClazz = {}

  static curThrowableCls = Java.use("java.lang.Throwable")

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  static {
    console.log("FridaAndroidUtil.cacheDictEnvClazz=" + FridaAndroidUtil.cacheDictEnvClazz)
    console.log("FridaAndroidUtil.curThrowableCls=" + FridaAndroidUtil.curThrowableCls)

    FridaAndroidUtil.JavaArray = Java.use('java.lang.reflect.Array')
    console.log("FridaAndroidUtil.JavaArray=" + FridaAndroidUtil.JavaArray)
    FridaAndroidUtil.JavaArrays = Java.use("java.util.Arrays")
    console.log("FridaAndroidUtil.JavaArrays=" + FridaAndroidUtil.JavaArrays)
    FridaAndroidUtil.JavaArrayList = Java.use('java.util.ArrayList')
    console.log("FridaAndroidUtil.JavaArrayList=" + FridaAndroidUtil.JavaArrayList)

    FridaAndroidUtil.JavaByteArr = Java.use("[B")
    console.log("FridaAndroidUtil.JavaByteArr=" + FridaAndroidUtil.JavaByteArr)
    // var JavaObjArr = Java.use("[Ljava.lang.Object")
    FridaAndroidUtil.JavaObjArr = Java.use("[Ljava.lang.Object;")
    console.log("FridaAndroidUtil.JavaObjArr=" + FridaAndroidUtil.JavaObjArr)
  }

  constructor() {
    console.log("FridaAndroidUtil constructor")
  }

  static printModuleInfo(moduleName){
    const foundModule = Module.load(moduleName)
    // const foundModule = Module.ensureInitialized()
    console.log("foundModule=" + foundModule)
  
    if (null == foundModule) {
      return
    }
  
    console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size" + foundModule.size + ", path=" + foundModule.path)
  
    var curSymbolList = foundModule.enumerateSymbols()
    console.log("Symbol: length=" + curSymbolList.length + ", list=" + curSymbolList)
    for(var i = 0; i < curSymbolList.length; i++) {
      console.log("---------- Symbol [" + i + "]----------")
      var curSymbol = curSymbolList[i]
      var sectionStr = JSON.stringify(curSymbol.section)
      console.log("name=" + curSymbol.name + ", address=" + curSymbol.address + "isGlobal=" + curSymbol.isGlobal + ", type=" + curSymbol.type + ", section=" + sectionStr)
    }
  
    var curExportList = foundModule.enumerateExports()
    console.log("Export: length=" + curExportList.length + ", list=" + curExportList)
    for(var i = 0; i < curExportList.length; i++) {
      console.log("---------- Export [" + i + "]----------")
      var curExport = curExportList[i]
      console.log("type=" + curExport.type + ", name=" + curExport.name + ", address=" + curExport.address)
    }
  }

  static waitForLibLoading(libraryName, callback_afterLibLoaded){
    console.log("libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    var android_dlopen_ext = Module.getExportByName(null, 'android_dlopen_ext')
    console.log("android_dlopen_ext=" + android_dlopen_ext)
    if (null == android_dlopen_ext) {
      return
    }
  
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function (args) {
        // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

        // console.log("args=" + args)
        var filenamePtr = args[0]
        var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
        // console.log("libFullPath=" + libFullPath)
        // var flags = args[1]
        // var info = args[2]
        // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        // if(libraryName === libFullPath){
        if(libFullPath.includes(libraryName)){
          console.log("+++ Loaded lib " + libraryName)
          this.isLibLoaded = true
        }
      },
  
      onLeave: function () {
        if (this.isLibLoaded) {
          callback_afterLibLoaded(libraryName)
  
          this.isLibLoaded = false
        }
      }
    })
  
  }

  static hookAfterLibLoaded(libName, callback_afterLibLoaded){
    console.log("libName=" + libName)
    FridaAndroidUtil.waitForLibLoading(libName, callback_afterLibLoaded)
  }

  static findSymbolFromLib(soLibName, jniFuncName, callback_isFound) {
    console.log("soLibName=" + soLibName + ", jniFuncName=" + jniFuncName + ", callback_isFound=" + callback_isFound)
  
    var foundSymbolList = []
    let libSymbolList = Module.enumerateSymbolsSync(soLibName)
    // console.log("libSymbolList=" + libSymbolList)
    for (let i = 0; i < libSymbolList.length; i++) {
        var curSymbol = libSymbolList[i]
        // console.log("[" + i  + "] curSymbol=" + curSymbol)
  
        var symbolName = curSymbol.name
        // console.log("[" + i  + "] symbolName=" + symbolName)

        // var isFound = callback_isFound(symbolName)
        var isFound = callback_isFound(curSymbol, jniFuncName)
        // console.log("isFound=" + isFound)
  
        if (isFound) {
          var symbolAddr = curSymbol.address
          // console.log("symbolAddr=" + symbolAddr)

          foundSymbolList.push(curSymbol)
          console.log("+++ Found [" + i + "] symbol: addr=" + symbolAddr + ", name=" + symbolName)
        }
    }
  
    // console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static findFunction_libart_so(jniFuncName, func_isFound) {
    var foundSymbolList = FridaAndroidUtil.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
    console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static isFoundSymbol(curSymbol, symbolName){
    // return symbolName.includes("NewStringUTF")
    // return symbolName.includes("CheckJNI12NewStringUTF")
    // return symbol.name.includes("CheckJNI12NewStringUTF")

    // _ZN3art12_GLOBAL__N_18CheckJNI12NewStringUTFEP7_JNIEnvPKc.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKc
    // _ZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_
    // _ZNK3art12_GLOBAL__N_119NewStringUTFVisitorclENS_6ObjPtrINS_6mirror6ObjectEEEm
    // _ZN3art2gc4Heap16AllocLargeObjectILb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadEPNS_6ObjPtrINS5_5ClassEEEmRKT0_
    // _ZZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb0ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_ENKUlvE_clEv
    // _ZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKc
    // _ZZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // _ZZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // return symbol.name.includes("NewStringUTF")

    // symbolName.includes("RegisterNatives") && symbolName.includes("CheckJNI")
    // return symbolName.includes("CheckJNI15RegisterNatives")
    // return symbolName.includes("RegisterNatives")

    // _ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // _ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // return symbol.name.includes("RegisterNatives")

    // return symbolName.includes("CheckJNI11GetMethodID")
    // return symbolName.includes("GetMethodID")

    // _ZN3art12_GLOBAL__N_18CheckJNI19GetMethodIDInternalEPKcP7_JNIEnvP7_jclassS3_S3_b
    // _ZN3art12_GLOBAL__N_18CheckJNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // _ZN3art3JNIILb1EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // return symbol.name.includes("GetMethodID")

    return curSymbol.name.includes(symbolName)
  }

  static findJniFunc(jniFuncName){
    var jniSymbolList = FridaAndroidUtil.findFunction_libart_so(jniFuncName, FridaAndroidUtil.isFoundSymbol)
    return jniSymbolList
  }

  static doHookJniFunc_multipleMatch(foundSymbolList, callback_onEnter, callback_onLeave=null){
    if (null == foundSymbolList){
      return
    }

    var symbolNum = foundSymbolList.length
    console.log("symbolNum=" + symbolNum)
    if (symbolNum == 0){
      return
    }

    for(var i = 0; i < symbolNum; ++i) {
      var eachSymbol = foundSymbolList[i]
      // console.log("eachSymbol=" + eachSymbol)
      var curSymbolAddr = eachSymbol.address
      console.log("curSymbolAddr=" + curSymbolAddr)

      Interceptor.attach(curSymbolAddr, {
        onEnter: function (args) {
          callback_onEnter(this, eachSymbol, args)
        },
        onLeave: function(retVal){
          if (null != callback_onLeave) {
            callback_onLeave(this, retVal)
          }
        }
      })
    }
  }

  static hookJniFunc(jniFuncName, hookFunc_onEnter, hookFunc_onLeave=null){
    var jniSymbolList = FridaAndroidUtil.findJniFunc(jniFuncName)
    FridaAndroidUtil.doHookJniFunc_multipleMatch(jniSymbolList, hookFunc_onEnter, hookFunc_onLeave)
  }

  static hookNative_NewStringUTF(){
    FridaAndroidUtil.hookJniFunc(
      "NewStringUTF",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged NewStringUTF [" + curSymbol.address + "]")
          // jstring NewStringUTF(JNIEnv *env, const char *bytes);
          var jniEnv = args[0]
          console.log("jniEnv=" + jniEnv)

          var newStrPtr = args[1]
          // var newStr = newStrPtr.readCString()
          // var newStr = FridaUtil.ptrToUtf8Str(newStrPtr)
          var newStr = FridaUtil.ptrToCStr(newStrPtr)
          console.log("newStrPtr=" + newStrPtr + " -> newStr=" + newStr)
      }
    )
  }

  static hookNative_GetMethodID(callback_enableLog=null){
    FridaAndroidUtil.hookJniFunc(
      "GetMethodID", 
      function(thiz, curSymbol, args){
        var curSymbolAddr = curSymbol.address

        // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
        var jniEnv = args[0]

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)

        var namePtr = args[2]
        var nameStr = FridaUtil.ptrToUtf8Str(namePtr)
        
        var sigPtr = args[3]
        var sigStr = FridaUtil.ptrToUtf8Str(sigPtr)

        thiz.enableLog = false
        if (callback_enableLog) {
          thiz.enableLog = callback_enableLog(jniEnv, jclassName, nameStr, sigStr)
        } else {
          thiz.enableLog = true          
        }

        if (thiz.enableLog) {
          JsUtil.logStr("Trigged GetMethodID [" + curSymbolAddr + "]")

          console.log("jniEnv=" + jniEnv)
          console.log("clazz=" + clazz + " -> jclassName=" + jclassName)
          console.log("namePtr=" + namePtr + " -> nameStr=" + nameStr)
          console.log("sigPtr=" + sigPtr + " -> sigStr=" + sigStr)

          // if ("com.bytedance.mobsec.metasec.ml.MS" == jclassName){
          //   console.log("curSymbolAddr=" + curSymbolAddr)
          //   var libArtFuncPtr_GetMethodID = curSymbolAddr
          //   console.log("libArtFuncPtr_GetMethodID=" + libArtFuncPtr_GetMethodID)
          //   // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
          //   var nativeFunc_GetMethodID = new NativeFunction(
          //     libArtFuncPtr_GetMethodID,
          //     // 'jmethodID',
          //     // 'int',
          //     'pointer',
          //     // ['pointer', 'jclass', 'pointer', 'pointer']
          //     // ['pointer', 'int', 'pointer', 'pointer']
          //     ['pointer', 'pointer', 'pointer', 'pointer']
          //     // ['JNIEnv*', 'jclass', 'char*', 'char*']
          //   )
          //   console.log("nativeFunc_GetMethodID=" + nativeFunc_GetMethodID)
          //   // console.log("jniEnv=" + jniEnv + ", clazz=" + clazz + " -> jclassName=" + jclassName)
          //   // var funcName_Bill = "Bill"
          //   // var funcSig_Bill = "()V"
          //   var funcSig_common = Memory.allocUtf8String("()V")
          //   console.log("funcSig_common=" + funcSig_common)

          //   var funcName_Bill = Memory.allocUtf8String("Bill")
          //   console.log("funcName_Bill=" + funcName_Bill)
          //   var jMethodID_Bill = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Bill, funcSig_common)
          //   console.log("jMethodID_Bill=" + jMethodID_Bill)

          //   var funcName_Louis = Memory.allocUtf8String("Louis")
          //   console.log("funcName_Louis=" + funcName_Louis)
          //   var jMethodID_Louis = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Louis, funcSig_common)
          //   console.log("jMethodID_Louis=" + jMethodID_Louis)

          //   var funcName_Zeoy = Memory.allocUtf8String("Zeoy")
          //   console.log("funcName_Zeoy=" + funcName_Zeoy)
          //   var jMethodID_Zeoy = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Zeoy, funcSig_common)
          //   console.log("jMethodID_Zeoy=" + jMethodID_Zeoy)

          //   var funcName_Francies = Memory.allocUtf8String("Francies")
          //   console.log("funcName_Francies=" + funcName_Francies)
          //   var jMethodID_Francies = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Francies, funcSig_common)
          //   console.log("jMethodID_Francies=" + jMethodID_Francies)
          // }

        }
      },
      function(thiz, retVal){
        if (thiz.enableLog) {
          console.log("GetMethodID retVal=" + retVal)
        }
      }
    )
  }

  /* print detail of JNINativeMethod:

    typedef struct {
      const char* name;
      const char* signature;
      void* fnPtr;
    } JNINativeMethod;
  */
  static printJNINativeMethodDetail(methodsPtr, methodNum){
    // console.log("methodsPtr=" + methodsPtr + ", methodNum=" + methodNum)

    // console.log("Process.pointerSize=" + Process.pointerSize) // 8
    let JNINativeMethod_size = Process.pointerSize * 3
    // console.log("JNINativeMethod_size=" + JNINativeMethod_size) // 24

    for (var i = 0; i < methodNum; i++) {
      JsUtil.logStr("method [" + i + "]", true, "-", 80)

      var curPtrStartPos = i * JNINativeMethod_size
      // console.log("curPtrStartPos=" + curPtrStartPos)

      var namePtrPos = methodsPtr.add(curPtrStartPos)
      // console.log("namePtrPos=" + namePtrPos)
      var namePtr = Memory.readPointer(namePtrPos)
      // console.log("namePtr=" + namePtr)
      // var nameStr = Memory.readCString(namePtr)
      var nameStr = FridaUtil.ptrToCStr(namePtr)
      // console.log("nameStr=" + nameStr)
      console.log("name: pos=" + namePtrPos + " -> ptr=" + namePtr + " -> str=" + nameStr)

      var sigPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize)
      // var sigPtrPos = namePtrPos.add(Process.pointerSize)
      // console.log("sigPtrPos=" + sigPtrPos)
      var sigPtr = Memory.readPointer(sigPtrPos)
      // console.log("sigPtr=" + sigPtr)
      var sigStr = FridaUtil.ptrToCStr(sigPtr)
      // console.log("sigStr=" + sigStr)
      console.log("signature: pos=" + sigPtrPos + " -> ptr=" + sigPtr + " -> str=" + sigStr)

      var fnPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize*2)
      // var fnPtrPos = sigPtrPos.add(Process.pointerSize)
      // console.log("fnPtrPos=" + fnPtrPos)
      var fnPtrPtr = Memory.readPointer(fnPtrPos)
      // console.log("fnPtrPtr=" + fnPtrPtr)
      var foundModule = Process.findModuleByAddress(fnPtrPtr)
      // console.log("foundModule=" + foundModule)
      var moduleBase = foundModule.base
      // console.log("moduleBase=" + moduleBase)
      var offsetInModule = ptr(fnPtrPtr).sub(moduleBase)
      // console.log("offsetInModule=" + offsetInModule)
      console.log("fnPtr: pos=" + fnPtrPos + " -> ptr=" + fnPtrPtr + " -> offset=" + offsetInModule)

      console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size=" + foundModule.size_ptr + ", path=" + foundModule.path)
    }
  }

  static hookNative_RegisterNatives(){
    // var symbolList_RegisterNatives = find_RegisterNatives()
    // hoook_RegisterNatives(symbolList_RegisterNatives)

    FridaAndroidUtil.hookJniFunc(
      "RegisterNatives",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged RegisterNatives [" + curSymbol.address + "]")

        // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
        var jniEnv = args[0]
        console.log("jniEnv=" + jniEnv)

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)
        console.log("clazz=" + clazz + " -> jclassName=" + jclassName)

        var methodsPtr = args[2]
        console.log("methodsPtr=" + methodsPtr)

        var nMethods = args[3]
        var methodNum = parseInt(nMethods)
        console.log("nMethods=" + nMethods + " -> methodNum=" + methodNum)

        FridaAndroidUtil.printJNINativeMethodDetail(methodsPtr, methodNum)
      }
  )

  }

  // java byte array to js byte array
  static javaByteArrToJsByteArr(javaByteArr){
    // var javaByteArrLen = javaByteArr.length
    // console.log("javaByteArrLen=" + javaByteArrLen) // javaByteArrLen=undefined
    var javaByteArrGotLen = FridaAndroidUtil.JavaArray.getLength(javaByteArr)
    console.log("javaByteArrGotLen=" + javaByteArrGotLen) // javaByteArrGotLen=8498
    var jsByteArr = new Array()
    // console.log("jsByteArr=" + jsByteArr)
    for(var i = 0; i < javaByteArrGotLen; ++i) {
      // jsByteArr[i] = javaByteArr[i]
      var curByte = FridaAndroidUtil.JavaArray.get(javaByteArr, i)
      // console.log("curByte=" + curByte)
      jsByteArr[i] = curByte
    }
    // console.log("jsByteArr=" + jsByteArr)
    return jsByteArr
  }

  // java array/list (byte array / List<Integer> )to string
  static javaArrayListToStr(javaArraryList){
    var jsArrayList = FridaAndroidUtil.javaByteArrToJsByteArr(javaArraryList)
    console.log("jsArrayList=" + jsArrayList)
    var jsArrayListStr = jsArrayList.toString()
    console.log("jsArrayListStr=" + jsArrayListStr)
    return jsArrayListStr
  }

  // get java class name from clazz
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  //  clazz=0x42a6 -> jclassName=java.lang.Integer
  // static getJclassName(clazz){
  // Note: if not use cache, some time will cause Frida crashed: Process terminated
  static getJclassName(clazz, isUseCache=true){
  // static getJclassName(clazz, isUseCache=false){
    // console.log("clazz=" + clazz)
    var isFoundCache = false
    var isNeedAddToCache = false
    var className = ""

    if (null == clazz){
      return className
    }

    var env = Java.vm.tryGetEnv()
    // console.log("env=" + env) // env=[object Object]
    if (null == env){
      return className
    }

    // console.log("isUseCache=" + isUseCache)
    if(isUseCache){
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var cachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        if (clazz in cachedClazzClassnameDict) {
          className = cachedClazzClassnameDict[clazz]
          if (JsUtil.strIsEmpty(className)){
            console.warn("clazz=" + clazz + " in cache=" + cachedClazzClassnameDict + ", but empty className")
          } else {
            isFoundCache = true
          }
        }
        else {
          // console.log("clazz=" + clazz + " not in cache=" + cachedClazzClassnameDict)
        }
      }
      else {
        // console.log("env=" + env + " not in cache=" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    // console.log("isFoundCache=" + isFoundCache)
    if (!isFoundCache){
      // var clazzInt = clazz.toInt32(clazzInt)
      // // console.log("clazzInt=" + clazzInt)
      // const ProbablyErrorMinClazzValue = 0x1000
      // var isProbabllyError = clazzInt < ProbablyErrorMinClazzValue
      // if (isProbabllyError) {
      //   // console.warn("Not do getClassName, for probably erro for clazz=" + clazz + ", less then ProbablyErrorMinClazzValue=" + ProbablyErrorMinClazzValue)
      // } else {
      try {
        className = env.getClassName(clazz)
      } catch(err){
        console.error("getJclassName catch: err=" + err + ", for clazz=" + clazz)
      } finally {
        if (JsUtil.strIsEmpty(className)){
          console.error("getJclassName finally: empty className for clazz=" + clazz)
        } else {
          // console.log("getJclassName OK: clazz=" + clazz + " -> className=" + className)
          if (isUseCache){
            isNeedAddToCache = true
          }
        }
      }
      // }
    }

    if (isUseCache && isNeedAddToCache){  
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var oldCachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        // console.log("old CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        oldCachedClazzClassnameDict[clazz] = className
        // console.log("new CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        FridaAndroidUtil.cacheDictEnvClazz[env] = oldCachedClazzClassnameDict
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to existed env cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      } else {
        FridaAndroidUtil.cacheDictEnvClazz[env] = {
          clazz: className
        }
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    var logPrefix = ""
    if (isFoundCache){
      logPrefix = "Cached: "
    }

    // console.log("className=" + className)
    // console.log(logPrefix + "clazz=" + clazz + "-> className=" + className)
    return className
  }

  static getJavaClassName(curObj){
    var javaClsName = null
    if (null != curObj) {
      // javaClsName = curObj.constructor.name
      javaClsName = curObj.$className
      // console.log("javaClsName=" + javaClsName)
      // var objType = (typeof curObj)
      // console.log("objType=" + objType)
    }
    // console.log("javaClsName=" + javaClsName)
    return javaClsName
  }

  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaAndroidUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  } 

  // convert (Java) map (java.util.HashMap) key=value string list
  static mapToKeyValueStrList(curMap){
    var keyValStrList = []
    var HashMapNode = Java.use('java.util.HashMap$Node')
    // console.log("HashMapNode=" + HashMapNode)
    if((null != curMap) && (curMap != undefined)) {
      var mapEntrySet = curMap.entrySet()
      // console.log("mapEntrySet=" + mapEntrySet)
      if (mapEntrySet != undefined) {
        var iterator = mapEntrySet.iterator()
        // console.log("iterator=" + iterator)
        while (iterator.hasNext()) {
          var entry = Java.cast(iterator.next(), HashMapNode)
          // console.log("entry=" + entry)
          var curKey = entry.getKey()
          var curVal = entry.getValue()
          // console.log("key=" + entry.getKey() + ", value=" + entry.getValue());
          var keyValStr = `${curKey}=${curVal}`
          // console.log("keyValStr=" + keyValStr);
          keyValStrList.push(keyValStr)
        }  
      }  
    }
    // console.log("keyValStrList=" + keyValStrList)
    return keyValStrList
  }

  // convert (Java) map (java.util.HashMap) to string
  //  curMap="<instance: java.util.Map, $className: java.util.HashMap>"
  static mapToStr(curMap){
    // return JSON.stringify(curMap, (key, value) => (value instanceof Map ? [...value] : value));
    // var keyValStrList = this.mapToKeyValueStrList(curMap)
    var keyValStrList = FridaAndroidUtil.mapToKeyValueStrList(curMap)
    // console.log("keyValStrList=" + keyValStrList)
    var mapStr = keyValStrList.join(", ")
    var mapStr = `[${mapStr}]`
    // console.log("mapStr=" + mapStr)
    return mapStr
  }

  static describeJavaClass(className) {
    var jClass = Java.use(className);
    console.log(JSON.stringify({
      _name: className,
      _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertyDescriptor(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertySymbols(jClass.__proto__).filter(m => {
        return !m.startsWith('$') // filter out Frida related special properties
           || m == 'class' || m == 'constructor' // optional
      }), 
      _fields: jClass.class.getFields().map(f => {
        return f.toString()
      })  
    }, null, 2))
  }

  // enumerate all methods declared in a Java class
  static enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();
    console.log("use getDeclaredMethods")

    // var ownMethods = hook.class.getMethods();
    // console.log("use getMethods")

    hook.$dispose;
    return ownMethods;
  }

  // enumerate all property=field declared in a Java class
  static enumProperties(targetClass) {
    var hook = Java.use(targetClass);
    // var ownMethods = hook.class.getFields();
    // console.log("use getFields")

    var ownFields = hook.class.getDeclaredFields();
    console.log("use getDeclaredFields")

    hook.$dispose;
    return ownFields;
  }

  // print single java class all Functions=Methods and Fields=Properties
  static printClassAllMethodsFields(javaClassName) {
    console.log("=============== " + "Class: " + javaClassName + " ===============")

    console.log("-----" + "All Properties" + "-----")
    // var allProperties = enumProperties(javaClassName)
    // var allProperties = this.enumProperties(javaClassName)
    var allProperties = FridaAndroidUtil.enumProperties(javaClassName)
    allProperties.forEach(function(singleProperty) { 
      console.log(singleProperty)
    })

    // console.log("-----" + "All Methods" + "-----")
    // enumerate all methods in a class
    // var allMethods = enumMethods(javaClassName)
    // var allMethods = this.enumMethods(javaClassName)
    var allMethods = FridaAndroidUtil.enumMethods(javaClassName)
    allMethods.forEach(function(singleMethod) { 
      console.log(singleMethod)
    })

    // console.log("")
    console.log("=========== " + "End of class: " + javaClassName + " ===========")
  }

  // generate current stack trace string
  static genStackStr(prefix="") {
    // let newThrowable = ThrowableCls.$new()
    // let newThrowable = this.curThrowableCls.$new()
    let newThrowable = FridaAndroidUtil.curThrowableCls.$new()
    // console.log("genStackStr: newThrowable=" + newThrowable)
    var stackElements = newThrowable.getStackTrace()
    // console.log("genStackStr: stackElements=" + stackElements)
    if (!JsUtil.strIsEmpty(prefix)){
      prefix = prefix + " "
    }
    const linePrefix = "\n  "
    var stackStr = prefix + "Stack:" + linePrefix + stackElements[0] //method//stackElements[0].getMethodName()
    for (var i = 1; i < stackElements.length; i++) {
      stackStr += linePrefix + "at " + stackElements[i]
    }
    // stackStr = "\n\n" + stackStr
    stackStr = stackStr + "\n"
    // console.log("genStackStr: stackStr=" + stackStr)

    return stackStr
  }

  // 打印当前调用堆栈信息 print call stack
  static printStack(prefix="") {
    var stackStr = FridaAndroidUtil.genStackStr(prefix)
    console.log(stackStr)

    // let newThrowable = ThrowableCls.$new()
    // let curLog = Java.use("android.util.Log")
    // let stackStr = curLog.getStackTraceString(newThrowable)
    // console.log("stackStr=" + stackStr)
  }

  // generate Function call string
  static genFunctionCallStr(funcName, funcParaDict){
    var logStr = `${funcName}:`
    // var logStr = funcName + ":"
    var isFirst = true

    for(var curParaName in funcParaDict){
      let curParaValue = funcParaDict[curParaName]
      var prevStr = ""
      if (isFirst){
        prevStr = " "
        isFirst = false
      } else {
        prevStr = ", "
      }

      logStr = `${logStr}${prevStr}${curParaName}=` + curParaValue
      // logStr = logStr + prevStr + curParaName + "=" + curParaValue
    }

    return logStr
  }

  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }

  // print Function call and stack trace string
  static printFunctionCallAndStack(funcName, funcParaDict, filterList=undefined){
    // console.log("filterList=" + filterList)

    var needPrint = true

    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

    // var stackStr = this.genStackStr()
    // var stackStr = FridaAndroidUtil.genStackStr()
    var stackStr = FridaAndroidUtil.genStackStr(funcName)

    if (filterList != undefined) {
      needPrint = false

      for (const curFilter of filterList) {
        // console.log("curFilter=" + curFilter)
        if (stackStr.includes(curFilter)) {
          needPrint = true
          // console.log("needPrint=" + needPrint)
          break
        }
      }
    }

    if (needPrint) {
      var functionCallAndStackStr = `${functionCallStr}\n${stackStr}`
      // var functionCallAndStackStr = functionCallStr + "\n" + stackStr
    
      // return functionCallAndStackStr
      console.log(functionCallAndStackStr)  
    }
  }

  // find loaded classes that match a pattern (async)
  // Note: for some app, will crash: Process terminated
  static findClass(pattern) {
    console.log("Finding all classes that match pattern: " + pattern + "\n");

    Java.enumerateLoadedClasses({
      onMatch: function(aClass) {
        if (aClass.match(pattern)){
          console.log(aClass)
        }
      },
      onComplete: function() {}
    });
  }

  // emulate print all Java Classes
  // Note: for some app, will crash: Process terminated
  static printAllClasses() {
    // findClass("*")

    Java.enumerateLoadedClasses({
      onMatch: function(className) {
        console.log(className);
      },
      onComplete: function() {}
    });
  }

}

// hook common Android/Java class
class HookAndroidJava {
  constructor() {
    console.log("HookAndroidJava constructor")
  }

  static JSONObject() {
    /******************** org.json.JSONObject ********************/
    var className_JSONObject = "org.json.JSONObject"
    // FridaAndroidUtil.printClassAllMethodsFields(className_JSONObject)

    var cls_JSONObject = Java.use(className_JSONObject)
    console.log("cls_JSONObject=" + cls_JSONObject)

    // public org.json.JSONObject org.json.JSONObject.put(java.lang.String,java.lang.Object) throws org.json.JSONException
    var func_JSONObject_put = cls_JSONObject.put.overload('java.lang.String', 'java.lang.Object')
    console.log("func_JSONObject_put=" + func_JSONObject_put)
    if (func_JSONObject_put) {
      func_JSONObject_put.implementation = function (str, obj) {
        var funcName = "JSONObject.put(str,obj)"
        var funcParaDict = {
          "str": str,
          "obj": obj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.put(str, obj)
      }
    }

  }

  static String(callback_String_equals=null) {
    /******************** java.lang.String ********************/
    var className_String = "java.lang.String"
    // FridaAndroidUtil.printClassAllMethodsFields(className_String)

    var cls_String = Java.use(className_String)
    console.log("cls_String=" + cls_String)

    // public String(String original)
    var func_String_ctor = cls_String.$init.overload('java.lang.String')
    // var func_String_ctor = cls_String.getInstance.overload('java.lang.String')
    // var func_String_ctor = cls_String.$new.overload('java.lang.String')
    console.log("func_String_ctor=" + func_String_ctor)
    if (func_String_ctor) {
      func_String_ctor.implementation = function (original) {
        var funcName = "String(orig)"
        var funcParaDict = {
          "original": original,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.$init(original)
      }
    }

    // public boolean equals(Object anObject)
    // public boolean java.lang.String.equals(java.lang.Object)
    var func_String_equals = cls_String.equals
    console.log("func_String_equals=" + func_String_equals)
    if (func_String_equals) {
      func_String_equals.implementation = function (anObject) {
        var funcName = "String.equals(anObject)"
        var funcParaDict = {
          "anObject": anObject,
        }

        var isPrintStack = false
        if(null != callback_String_equals) {
          isPrintStack = callback_String_equals(anObject)
        }

        if(isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.equals(anObject)
      }
    }

  }

  static URL(callback_isPrintStack_URL_init=null) {
    var className_URL = "java.net.URL"
    // FridaAndroidUtil.printClassAllMethodsFields(className_URL)

    var cls_URL = Java.use(className_URL)
    console.log("cls_URL=" + cls_URL)

    // public URL(String url)
    // var func_URL_init = cls_URL.$init
    var func_URL_init = cls_URL.$init.overload('java.lang.String')
    console.log("func_URL_init=" + func_URL_init)
    if (func_URL_init) {
      func_URL_init.implementation = function (url) {
        var funcName = "URL(url)"
        var funcParaDict = {
          "url": url,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_URL_init){
          isPrintStack = callback_isPrintStack_URL_init(url)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.$init(url)
      }
    }
  }

  static HashMap(callback_isPrintStack_put=null, callback_isPrintStack_putAll=null, callback_isPrintStack_get=null) {
    /******************** java.util.HashMap ********************/
    var className_HashMap = "java.util.HashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_HashMap)

    var cls_HashMap = Java.use(className_HashMap)
    console.log("cls_HashMap=" + cls_HashMap)
    // var instance_HashMap = cls_HashMap.$new()
    // console.log("instance_HashMap=" + instance_HashMap)

    // public java.lang.Object java.util.HashMap.put(java.lang.Object,java.lang.Object)
    // var func_HashMap_put = cls_HashMap.put('java.lang.Object', 'java.lang.Object')
    // var func_HashMap_put = instance_HashMap.put('java.lang.Object', 'java.lang.Object')
    var func_HashMap_put = cls_HashMap.put
    console.log("func_HashMap_put=" + func_HashMap_put)
    if (func_HashMap_put) {
      func_HashMap_put.implementation = function (keyObj, valueObj) {
        var funcName = "HashMap.put(key,val)"
        var funcParaDict = {
          "keyObj": keyObj,
          "valueObj": valueObj,
        }

        if (null != keyObj) {
          // console.log("keyObj=" + keyObj)
          // console.log("keyObj.value=" + keyObj.value)
          // console.log("keyObj=" + keyObj + ", valueObj=" + valueObj)

          var isPrintStack = false

          // isPrintStack = HookDouyin_feedUrl.HashMap(keyObj, valueObj)
          if (null != callback_isPrintStack_put){
            isPrintStack = callback_isPrintStack_put(keyObj, valueObj)
          }

          if (isPrintStack) {
            FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          }
        }

        return this.put(keyObj, valueObj)
      }
    }

    // public void java.util.HashMap.putAll(java.util.Map)
    // var func_HashMap_putAll = cls_HashMap.putAll('java.util.Map')
    var func_HashMap_putAll = cls_HashMap.putAll
    console.log("func_HashMap_putAll=" + func_HashMap_putAll)
    if (func_HashMap_putAll) {
      func_HashMap_putAll.implementation = function (newMap) {
        var funcName = "HashMap.putAll(map)"
        var funcParaDict = {
          "newMap": newMap,
        }
        // console.log("newMap=" + newMap)
        var isPrintStack = false
        if (null != callback_isPrintStack_putAll){
          isPrintStack = callback_isPrintStack_putAll(newMap)
        }

        if (isPrintStack){
          console.log("newMapStr=" + FridaAndroidUtil.mapToStr(newMap))
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.putAll(newMap)
      }
    }

    // https://docs.oracle.com/javase/8/docs/api/java/util/HashMap.html#get-java.lang.Object-
    // public V get(Object key)
    var func_HashMap_get = cls_HashMap.get
    console.log("func_HashMap_get=" + func_HashMap_get)
    if (func_HashMap_get) {
      func_HashMap_get.implementation = function (keyObj) {
        var funcName = "HashMap.get(key)"
        var funcParaDict = {
          "keyObj": keyObj,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_get){
          isPrintStack = callback_isPrintStack_get(keyObj)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retValObj = this.get(keyObj)
        if (isPrintStack){
          console.log("retValObj=" + retValObj)
        }
        return retValObj
      }
    }

  }
  
  static LinkedHashMap() {
    /******************** java.util.LinkedHashMap ********************/
    var className_LinkedHashMap = "java.util.LinkedHashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_LinkedHashMap)

    var cls_LinkedHashMap = Java.use(className_LinkedHashMap)
    console.log("cls_LinkedHashMap=" + cls_LinkedHashMap)

  }

  static RandomAccessFile() {
    /******************** java.io.RandomAccessFile ********************/
    var className_RandomAccessFile = "java.io.RandomAccessFile"
    // FridaAndroidUtil.printClassAllMethodsFields(className_RandomAccessFile)

    var cls_RandomAccessFile = Java.use(className_RandomAccessFile)
    console.log("cls_RandomAccessFile=" + cls_RandomAccessFile)

    // public final java.nio.channels.FileChannel java.io.RandomAccessFile.getChannel()
    var func_RandomAccessFile_getChannel = cls_RandomAccessFile.getChannel
    console.log("func_RandomAccessFile_getChannel=" + func_RandomAccessFile_getChannel)
    if (func_RandomAccessFile_getChannel) {
      func_RandomAccessFile_getChannel.implementation = function () {
        var funcName = "RandomAccessFile.getChannel()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var fileChannel = this.getChannel()
        console.log("fileChannel=" + fileChannel)
        var filePathValue = this.path.value
        console.log("filePathValue=" + filePathValue)
        return fileChannel
      }
    }
  }

  static NetworkRequest_Builder(){
    var clsName_NetworkRequest_Builder = "android.net.NetworkRequest$Builder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_NetworkRequest_Builder)

    var cls_NetworkRequest_Builder = Java.use(clsName_NetworkRequest_Builder)
    console.log("cls_NetworkRequest_Builder=" + cls_NetworkRequest_Builder)

    // public Builder ()
    var func_NetworkRequest_Builder_ctor_void = cls_NetworkRequest_Builder.$init.overload()
    console.log("func_NetworkRequest_Builder_ctor_void=" + func_NetworkRequest_Builder_ctor_void)
    if (func_NetworkRequest_Builder_ctor_void) {
      func_NetworkRequest_Builder_ctor_void.implementation = function () {
        var funcName = "NetworkRequest$Builder()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var newBuilder_void = this.$init()
        console.log("newBuilder_void=" + newBuilder_void)
        return newBuilder_void
      }
    }

    // // Note: Xiaomi8 not exist: .overload('android.net.NetworkRequest')
    // //    -> Error: NetworkRequest$Builder(): specified argument types do not match any of: .overload()
    // // public Builder (NetworkRequest request)
    // var func_NetworkRequest_Builder_ctor_req = cls_NetworkRequest_Builder.$init.overload('android.net.NetworkRequest')
    // console.log("func_NetworkRequest_Builder_ctor_req=" + func_NetworkRequest_Builder_ctor_req)
    // if (func_NetworkRequest_Builder_ctor_req) {
    //   func_NetworkRequest_Builder_ctor_req.implementation = function (request) {
    //     var funcName = "NetworkRequest$Builder(request)"
    //     var funcParaDict = {
    //     }
    //     FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     var newBuilder_req = this.$init(request)
    //     console.log("newBuilder_req=" + newBuilder_req)
    //     return newBuilder_req
    //   }
    // }

  }

  static File(callback_File_ctor_str=null) {
    var className_File = "java.io.File"
    // FridaAndroidUtil.printClassAllMethodsFields(className_File)

    var cls_File = Java.use(className_File)
    console.log("cls_File=" + cls_File)

    // File(String pathname)
    var func_File_ctor_path = cls_File.$init.overload('java.lang.String')
    console.log("func_File_ctor_path=" + func_File_ctor_path)
    if (func_File_ctor_path) {
      func_File_ctor_path.implementation = function (pathname) {
        var funcName = "File(pathname)"
        var funcParaDict = {
          "pathname": pathname,
        }

        var isMatch = false
        if (null != callback_File_ctor_str){
          isMatch = callback_File_ctor_str(pathname)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        // tmp use previould check to bypass new File
        // if (isMatch) {
        //   // return null
        //   pathname = "" // hook bypass return empty File by empty filename
        // }

        var retFile_ctor_path = this.$init(pathname)

        // if (isMatch) {
          console.log("pathname=" + pathname + " => retFile_ctor_path=" + retFile_ctor_path)
        // }

        return retFile_ctor_path
      }
    }

    // public boolean exists ()
    var func_File_exists = cls_File.exists
    console.log("func_File_exists=" + func_File_exists)
    if (func_File_exists) {
      func_File_exists.implementation = function () {
        var funcName = "File.exists()"
        var funcParaDict = {
        }

        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBool_File_exists = this.exists()
        var fileAbsPath = this.getAbsolutePath()
        console.log("fileAbsPath=" + fileAbsPath + " => retBool_File_exists=" + retBool_File_exists)
        return retBool_File_exists
      }
    }

  }

  static Settings_getInt(cls_Settings, Settings_getInt_crName=null, Settings_getInt_crNameDef=null) {
    // static int	getInt(ContentResolver cr, String name)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    // public static int getInt (ContentResolver cr, String name)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    var func_Settings_getInt_crName = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String")
    console.log("func_Settings_getInt_crName=" + func_Settings_getInt_crName)
    if (func_Settings_getInt_crName) {
      func_Settings_getInt_crName.implementation = function (cr, name) {
        var funcName = "getInt(cr,name)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
        }

        var isMatch = false
        if (null != Settings_getInt_crName){
          isMatch = Settings_getInt_crName(cr, name)
        }

        var retInt_Settings_getInt_crName = 0

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crName = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crName = this.getInt(cr, name) // no hook
        } else {
          retInt_Settings_getInt_crName = this.getInt(cr, name)
        }

        console.log("name" + name + " => retInt_Settings_getInt_crName=" + retInt_Settings_getInt_crName)
        return retInt_Settings_getInt_crName
      }
    }

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String,int)

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String,int)

    var func_Settings_getInt_crNameDef = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int")
    console.log("func_Settings_getInt_crNameDef=" + func_Settings_getInt_crNameDef)
    if (func_Settings_getInt_crNameDef) {
      func_Settings_getInt_crNameDef.implementation = function (cr, name, def) {
        var funcName = "getInt(cr,name,def)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
          "def": def,
        }

        var isMatch = false
        if (null != Settings_getInt_crNameDef){
          isMatch = Settings_getInt_crNameDef(cr, name, def)
        }

        var retInt_Settings_getInt_crNameDef = 0

        if (isMatch){
          console.log("isMatch=" + isMatch)
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crNameDef = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def) // no hook
        } else {
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def)
        }

        console.log("name=" + name + " => retInt_Settings_getInt_crNameDef=" + retInt_Settings_getInt_crNameDef)
        return retInt_Settings_getInt_crNameDef
      }
    }

  }

  static SettingsGlobal(SettingsGlobal_getInt_crName=null, SettingsGlobal_getInt_crNameDef=null) {
    var className_SettingsGlobal = "android.provider.Settings$Global"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsGlobal)

    var cls_SettingsGlobal = Java.use(className_SettingsGlobal)
    console.log("cls_SettingsGlobal=" + cls_SettingsGlobal)

    HookAndroidJava.Settings_getInt(cls_SettingsGlobal, SettingsGlobal_getInt_crName, SettingsGlobal_getInt_crNameDef)
  }

  static SettingsSecure(SettingsSecure_getInt_crName=null, SettingsSecure_getInt_crNameDef=null) {
    var className_SettingsSecure = "android.provider.Settings$Secure"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsSecure)

    var cls_SettingsSecure = Java.use(className_SettingsSecure)
    console.log("cls_SettingsSecure=" + cls_SettingsSecure)

    HookAndroidJava.Settings_getInt(cls_SettingsSecure, SettingsSecure_getInt_crName, SettingsSecure_getInt_crNameDef)
  }

  static NetworkInterface(NetworkInterface_getName=null) {
    var className_NetworkInterface = "java.net.NetworkInterface"
    // FridaAndroidUtil.printClassAllMethodsFields(className_NetworkInterface)

    var cls_NetworkInterface = Java.use(className_NetworkInterface)
    console.log("cls_NetworkInterface=" + cls_NetworkInterface)

    // public String getName()
    // public java.lang.String java.net.NetworkInterface.getName()
    var func_NetworkInterface_getName = cls_NetworkInterface.getName
    console.log("func_NetworkInterface_getName=" + func_NetworkInterface_getName)
    if (func_NetworkInterface_getName) {
      func_NetworkInterface_getName.implementation = function () {
        var funcName = "NetworkInterface.getName()"
        var funcParaDict = {
        }

        var retName = this.getName()

        var isMatch = false
        if (null != NetworkInterface_getName){
          isMatch = NetworkInterface_getName(retName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // do hook bypass
          // retName = "fakeName"
          // retName = ""

          // no hook
        } else {
          // no hook
        }

        console.log("retName=" + retName)
        return retName
      }
    }

  }

  static PackageManager(PackageManager_getApplicationInfo=null) {
    var className_PackageManager = "android.content.pm.PackageManager"
    // FridaAndroidUtil.printClassAllMethodsFields(className_PackageManager)

    var cls_PackageManager = Java.use(className_PackageManager)
    console.log("cls_PackageManager=" + cls_PackageManager)

    // // Note: Xiaomi8 not exist: getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // public ApplicationInfo getApplicationInfo(String packageName, PackageManager.ApplicationInfoFlags flags)
    // // public android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager.ApplicationInfoFlags')
    // console.log("func_PackageManager_getApplicationInfo=" + func_PackageManager_getApplicationInfo)
    // if (func_PackageManager_getApplicationInfo) {
    //   func_PackageManager_getApplicationInfo.implementation = function (packageName, flags) {
    //     var funcName = "PackageManager.getApplicationInfo(packageName,flags)"
    //     var funcParaDict = {
    //       "packageName": packageName,
    //       "flags": flags,
    //     }

    //     var retAppInfo = this.getApplicationInfo(packageName, flags)

    //     var isMatch = false
    //     if (null != PackageManager_getApplicationInfo){
    //       isMatch = PackageManager_getApplicationInfo(packageName)
    //     }

    //     if (isMatch){
    //       FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

    //       // do hook bypass
    //       retAppInfo = ApplicationInfo()
    //     } else {
    //       // no hook
    //     }

    //     console.log("retAppInfo=" + retAppInfo)
    //     return retAppInfo
    //   }
    // }

    // public abstract ApplicationInfo getApplicationInfo (String packageName, int flags)
    // public abstract android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getApplicationInfo_abstract = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'int')
    console.log("func_PackageManager_getApplicationInfo_abstract=" + func_PackageManager_getApplicationInfo_abstract)
    if (func_PackageManager_getApplicationInfo_abstract) {
      func_PackageManager_getApplicationInfo_abstract.implementation = function (pkgName, flags) {
        var funcName = "PackageManager.getApplicationInfo(pkgName,flags)"
        var funcParaDict = {
          "pkgName": pkgName,
          "flags": flags,
        }

        var retAppInfo_abstract = this.getApplicationInfo(pkgName, flags)

        var isMatch = false
        if (null != PackageManager_getApplicationInfo){
          isMatch = PackageManager_getApplicationInfo(pkgName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // // do hook bypass
          // retAppInfo_abstract = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo_abstract=" + retAppInfo_abstract)
        return retAppInfo_abstract
      }
    }

  }

  static System(callback_isMatch_System_getProperty=null) {
    var className_System = "java.lang.System"
    // FridaAndroidUtil.printClassAllMethodsFields(className_System)

    var cls_System = Java.use(className_System)
    console.log("cls_System=" + cls_System)

    // public static String getProperty(String key) 
    // public static java.lang.String java.lang.System.getProperty(java.lang.String)
    var func_System_getProperty_key = cls_System.getProperty.overload('java.lang.String')
    console.log("func_System_getProperty_key=" + func_System_getProperty_key)
    if (func_System_getProperty_key) {
      func_System_getProperty_key.implementation = function (key) {
        var funcName = "System.getProperty(key)"
        var funcParaDict = {
          "key": key,
        }

        var isMatch = false
        if (null != callback_isMatch_System_getProperty){
          isMatch = callback_isMatch_System_getProperty(key)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retPropVal = this.getProperty(key)
        if (isMatch){
          retPropVal = null // enable hook bypass: return null
          console.log("key=" + key + " -> hooked retPropVal=" + retPropVal)
        } else {
          console.log("key=" + key + " -> retPropVal=" + retPropVal)
        }

        return retPropVal
      }
    }
  }

}