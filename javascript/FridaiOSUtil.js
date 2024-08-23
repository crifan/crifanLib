/*
	File: FridaiOSUtil.js
	Function: crifan's common Frida iOS Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/FridaiOSUtil.js
	Updated: 20240823
*/

// Frida iOS Util
class FridaiOSUtil {

  /*******************************************************************************
   * Config && Settings
  *******************************************************************************/
  // Print Function Stack Call
  static isUseCache = true
  // print only once stack for every function
  static isPrintOnlyOnceStack = true

  /*******************************************************************************
   * Global Variables
  *******************************************************************************/


  static gAddrToModuleInfoDict = {}
  static gModulePathToSlideDict = {}
  static gModulePathToClassesDict = {}
  static gModulePathAddrToSymbolDict = {}
  static gClassnameToAllMethodsDict = {}

  static free = null
  static objc_getClass = null
  static class_copyMethodList = null
  static objc_getMetaClass = null
  static method_getName = null
  static dladdr = null
  static _dyld_image_count = null
  static _dyld_get_image_name = null
  static _dyld_get_image_vmaddr_slide = null
  static objc_copyClassNamesForImage = null

  static {
    FridaiOSUtil.initCommonLibFunctions()
  }

  constructor() {
    console.log("FridaiOSUtil constructor")
  }

  // convert from frida function call to ObjC function call
  // "NSURL", "- initWithString:" => "-[NSURL initWithString:]"
  static toiOSObjcCall(class_name, method_name){
    const instanceCallStart = "-[" + class_name + " ";
    const classCallStart = "+[" + class_name + " ";
    var objcFuncCall = method_name.replace("- ", instanceCallStart);
    objcFuncCall = objcFuncCall.replace("+ ", classCallStart);
    objcFuncCall = objcFuncCall + "]";
    // console.log(class_name + " -> " + method_name + " => " + objcFuncCall);
    return objcFuncCall;
  }

  // convert from ObjC function call to frida function call
  // "-[NSURL initWithString:]" => ["NSURL", "- initWithString:"]
  static toFridaObjcCall(fridaObjcCallStr){
    // console.log("fridaObjcCallStr=" + fridaObjcCallStr)
    const funcCallP = /^([+-])\[(\w+)\s+([\w:]+)\]$/
    // console.log("funcCallP=" + funcCallP)
    const funcCallMatch = fridaObjcCallStr.match(funcCallP)
    // console.log("funcCallMatch=" + funcCallMatch)
    const objcFuncTypeChar = funcCallMatch[1]
    const objcClassName = funcCallMatch[2]
    const objcFuncName = funcCallMatch[3]
    const fridaFuncCallList = [objcClassName, objcFuncTypeChar + " " + objcFuncName]
    // console.log("fridaFuncCallList=" + fridaFuncCallList)
    return fridaFuncCallList
  }

  /* Convert args to real Javascript Array

    Note: 
      Interceptor.attach onEnter(args), args is not real JS array -> later operation will fail
        args.slice(2)
        Array.from(args)
      -> so need here to conver to real Array, then all is OK
  */
  static objcArgsToArgArray(args, realArgCount){
    var argsArr = Array()
    // console.log("initial: argsArr=" + argsArr)
    argsArr.push(args[0])
    argsArr.push(args[1])
    // console.log("add frist two: argsArr=" + argsArr)

    for (let curArgIdx = 0; curArgIdx < realArgCount; curArgIdx++) {
      const curArg = args[curArgIdx + 2]
      argsArr.push(curArg)
    }
    // console.log("add all args: argsArr=" + argsArr)
    return argsArr
  }

  /******************** iOS Common Lib Functions ********************/

  static initCommonLibFunctions(){
    console.log("Init common functions in common libs:")

    // free
    FridaiOSUtil.free = new NativeFunction(
      Module.findExportByName(null, 'free'),
      'void',
      ['pointer']
    )
    console.log("FridaiOSUtil.free=" + FridaiOSUtil.free)

    FridaiOSUtil.objc_getClass = new NativeFunction(
      Module.findExportByName(null, 'objc_getClass'),
      'pointer',
      ['pointer']
    )
    console.log("FridaiOSUtil.objc_getClass=" + FridaiOSUtil.objc_getClass)

    FridaiOSUtil.class_copyMethodList = new NativeFunction(
      Module.findExportByName(null, 'class_copyMethodList'),
      'pointer',
      ['pointer', 'pointer']
    )
    console.log("FridaiOSUtil.class_copyMethodList=" + FridaiOSUtil.class_copyMethodList)

    FridaiOSUtil.objc_getMetaClass = new NativeFunction(
      Module.findExportByName(null, 'objc_getMetaClass'),
      'pointer',
      ['pointer']
    )
    console.log("FridaiOSUtil.objc_getMetaClass=" + FridaiOSUtil.objc_getMetaClass)

    FridaiOSUtil.method_getName = new NativeFunction(
      Module.findExportByName(null, 'method_getName'),
      'pointer',
      ['pointer']
    )
    console.log("FridaiOSUtil.method_getName=" + FridaiOSUtil.method_getName)

    /*
    int dladdr(const void *, Dl_info *);

    typedef struct dl_info {
            const char      *dli_fname;     // Pathname of shared object
            void            *dli_fbase;     // Base address of shared object
            const char      *dli_sname;     // Name of nearest symbol
            void            *dli_saddr;     // Address of nearest symbol
    } Dl_info;

    */
    FridaiOSUtil.dladdr = new NativeFunction(
      Module.findExportByName(null, 'dladdr'),
      'int',
      ['pointer','pointer']
    )
    console.log("FridaiOSUtil.dladdr=" + FridaiOSUtil.dladdr)

    // uint32_t  _dyld_image_count(void)
    FridaiOSUtil._dyld_image_count = new NativeFunction(
      Module.findExportByName(null, '_dyld_image_count'),
      'uint32',
      []
    )
    console.log("FridaiOSUtil._dyld_image_count=" + FridaiOSUtil._dyld_image_count)

    // const char*  _dyld_get_image_name(uint32_t image_index) 
    FridaiOSUtil._dyld_get_image_name = new NativeFunction(
      Module.findExportByName(null, '_dyld_get_image_name'),
      'pointer',
      ['uint32']
    )
    console.log("FridaiOSUtil._dyld_get_image_name=" + FridaiOSUtil._dyld_get_image_name)


    // intptr_t   _dyld_get_image_vmaddr_slide(uint32_t image_index)
    FridaiOSUtil._dyld_get_image_vmaddr_slide = new NativeFunction(
      Module.findExportByName(null, '_dyld_get_image_vmaddr_slide'),
      'pointer',
      ['uint32']
    )
    console.log("FridaiOSUtil._dyld_get_image_vmaddr_slide=" + FridaiOSUtil._dyld_get_image_vmaddr_slide)

    // const char * objc_copyClassNamesForImage(const char *image, unsigned int *outCount)
    FridaiOSUtil.objc_copyClassNamesForImage = new NativeFunction(
      Module.findExportByName(null, 'objc_copyClassNamesForImage'),
      'pointer',
      ['pointer', 'pointer']
    );
    console.log("FridaiOSUtil.objc_copyClassNamesForImage=" + FridaiOSUtil.objc_copyClassNamesForImage)
  }

  // https://github.com/4ch12dy/FridaLib/blob/master/iOS/iOSFridaLib.js

  // xia0 log
  static XLOG(log) {
    console.log("[*] " + log)
  }

  // format string with width
  static format(str, width){	
    str = str + ""
    var len = str.length;
    
    if(len > width){
        return str
    }

    for(var i = 0; i < width-len; i++){
        str += " "
    }
    return str
  }

  static getExecFileName(modulePath){
    modulePath += ""
    return modulePath.split("/").pop()
  }

  // get module info from address
  static get_info_form_address(address){
    var moduleInfoDict = null
    var needAddToCache = false

    if (isUseCache){
      if (address in FridaiOSUtil.gAddrToModuleInfoDict){
        moduleInfoDict = FridaiOSUtil.gAddrToModuleInfoDict[address]
        // XLOG("Found: address=" + address + " in FridaiOSUtil.gAddrToModuleInfoDict, moduleInfoDict=" + JsUtil.toJsonStr(moduleInfoDict))
        return moduleInfoDict
      } else {
        needAddToCache = true
      }
    }

    var dl_info = Memory.alloc(Process.pointerSize*4);

    FridaiOSUtil.dladdr(ptr(address), dl_info)

    var dli_fname = Memory.readCString(Memory.readPointer(dl_info))
    var dli_fbase = Memory.readPointer(dl_info.add(Process.pointerSize))
    var dli_sname = Memory.readCString(Memory.readPointer(dl_info.add(Process.pointerSize*2)))
    var dli_saddr = Memory.readPointer(dl_info.add(Process.pointerSize*3))
    
    //XLOG("dli_fname:"+dli_fname)
    //XLOG("dli_fbase:"+dli_fbase)
    //XLOG("dli_sname:"+dli_sname)
    //XLOG("dli_saddr:"+dli_saddr)
    
    // var addrInfo = new Array();
    
    // addrInfo.push(dli_fname);
    // addrInfo.push(dli_fbase);
    // addrInfo.push(dli_sname);
    // addrInfo.push(dli_saddr);
    
    // //XLOG(addrInfo)
    // return addrInfo;

    moduleInfoDict = {
      "fileName": dli_fname,
      "fileAddress": dli_fbase,
      "symbolName": dli_sname,
      "symbolAddress": dli_saddr,
    }

    if (needAddToCache){
      // XLOG("Add: address=" + address + ", moduleInfoDict=" + JsUtil.toJsonStr(moduleInfoDict) + " into cache FridaiOSUtil.gAddrToModuleInfoDict")
      FridaiOSUtil.gAddrToModuleInfoDict[address] = moduleInfoDict
    }

    return moduleInfoDict
  }

  static get_image_vm_slide(modulePath){
    var moduleSlide = 0

    var needAddToCache = false

    if (isUseCache){
      if (modulePath in FridaiOSUtil.gModulePathToSlideDict){
        moduleSlide = FridaiOSUtil.gModulePathToSlideDict[modulePath]
        // XLOG("Found: modulePath=" + modulePath + " in FridaiOSUtil.gModulePathToSlideDict, moduleSlide=" + moduleSlide)
        return moduleSlide
      } else {
        needAddToCache = true
      }
    }

    var image_count = FridaiOSUtil._dyld_image_count()

    for (var i = 0; i < image_count; i++) {
        var image_name_ptr = FridaiOSUtil._dyld_get_image_name(i)
        var image_silde_ptr = FridaiOSUtil._dyld_get_image_vmaddr_slide(i)
        var image_name = Memory.readUtf8String(image_name_ptr)

        if (image_name == modulePath) {
            //XLOG(Memory.readUtf8String(image_name_ptr) + " slide:"+image_silde_ptr)
            // return image_silde_ptr
            moduleSlide = image_silde_ptr
            break
        }
        //XLOG(Memory.readUtf8String(image_name_ptr) + "slide:"+image_silde_ptr)
    }

    // return 0

    if (needAddToCache){
      // XLOG("Add: modulePath=" + modulePath + ", moduleSlide=" + moduleSlide + " into cache FridaiOSUtil.gModulePathToSlideDict")
      FridaiOSUtil.gModulePathToSlideDict[modulePath] = moduleSlide
    }

    return moduleSlide
  }

  static get_all_objc_class(modulePath){
    var classes = new Array()

    var needAddToCache = false

    if (isUseCache){
      if (modulePath in FridaiOSUtil.gModulePathToClassesDict){
        classes = FridaiOSUtil.gModulePathToClassesDict[modulePath]
        // XLOG("Found: modulePath=" + modulePath + " in FridaiOSUtil.gModulePathToClassesDict, classes=" + classes)
        // XLOG("Found: modulePath=" + modulePath + " in FridaiOSUtil.gModulePathToClassesDict, classes.length=" + classes.length)
        return classes
      } else {
        needAddToCache = true
      }
    }

    // if given modulePath nil, default is mainBundle
    if(!modulePath){
      var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    }else{
      var path = modulePath
    }

    // create args
    var pPath = Memory.allocUtf8String(path)
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)

    var pClasses = FridaiOSUtil.objc_copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    classes = new Array(count)

    for (var i = 0; i < count; i++) {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classes[i] = Memory.readUtf8String(pClassName)
    }

    FridaiOSUtil.free(pClasses)

    if (needAddToCache){
      // XLOG("Add: modulePath=" + modulePath + ", classes=" + classes + " into cache FridaiOSUtil.gModulePathToClassesDict")
      // XLOG("Add: modulePath=" + modulePath + ", classes.length=" + classes.length + " into cache FridaiOSUtil.gModulePathToClassesDict")
      FridaiOSUtil.gModulePathToClassesDict[modulePath] = classes
    }

    // XLOG(classes)
    return classes
  }

  static get_all_class_methods(classname){
    var allMethods = new Array()

    var needAddToCache = false

    if (isUseCache){
      if (classname in FridaiOSUtil.gClassnameToAllMethodsDict){
        allMethods = FridaiOSUtil.gClassnameToAllMethodsDict[classname]
        // XLOG("Found: classname=" + classname + " in FridaiOSUtil.gClassnameToAllMethodsDict, allMethods=" + toJsonStr(allMethods))
        // XLOG("Found: classname=" + classname + " in FridaiOSUtil.gClassnameToAllMethodsDict, allMethods.length=" + allMethods.length)
        return allMethods
      } else {
        needAddToCache = true
      }
    }

    // get objclass and metaclass
    var name = Memory.allocUtf8String(classname)
    var objClass = FridaiOSUtil.objc_getClass(name)
    var metaClass = FridaiOSUtil.objc_getMetaClass(name)
    
    // get obj class all methods
    var size_ptr = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(size_ptr, 0)
    var pObjMethods = FridaiOSUtil.class_copyMethodList(objClass, size_ptr)
    var count = Memory.readUInt(size_ptr)
    
    var allObjMethods = new Array()
    
    // get obj class all methods name and IMP
    for (var i = 0; i < count; i++) {
      var curObjMethod = new Array()
      var pObjMethodSEL = FridaiOSUtil.method_getName(pObjMethods.add(i * Process.pointerSize))
      var pObjMethodName = Memory.readCString(Memory.readPointer(pObjMethodSEL))
      var objMethodIMP = Memory.readPointer(pObjMethodSEL.add(2*Process.pointerSize))
      // XLOG("-["+classname+ " " + pObjMethodName+"]" + ":" + objMethodIMP)
      curObjMethod.push(pObjMethodName)
      curObjMethod.push(objMethodIMP)
      allObjMethods.push(curObjMethod)
    }
    
    var allMetaMethods = new Array()
    
    // get meta class all methods name and IMP
    var pMetaMethods = FridaiOSUtil.class_copyMethodList(metaClass, size_ptr)
    var count = Memory.readUInt(size_ptr)
    for (var i = 0; i < count; i++) {
      var curMetaMethod = new Array()
      
      var pMetaMethodSEL = FridaiOSUtil.method_getName(pMetaMethods.add(i * Process.pointerSize))
      var pMetaMethodName = Memory.readCString(Memory.readPointer(pMetaMethodSEL))
      var metaMethodIMP = Memory.readPointer(pMetaMethodSEL.add(2*Process.pointerSize))
      //XLOG("+["+classname+ " " + pMetaMethodName+"]" + ":" + metaMethodIMP)
      curMetaMethod.push(pMetaMethodName)
      curMetaMethod.push(metaMethodIMP)
      allMetaMethods.push(curMetaMethod)
    }
    
    allMethods.push(allObjMethods)
    allMethods.push(allMetaMethods)
    
    FridaiOSUtil.free(pObjMethods)
    FridaiOSUtil.free(pMetaMethods)

    if (needAddToCache){
      // XLOG("Add: classname=" + classname + ", allMethods=" + toJsonStr(allMethods) + " into cache FridaiOSUtil.gClassnameToAllMethodsDict")
      // XLOG("Add: classname=" + classname + ", allMethods.length=" + allMethods.length + " into cache FridaiOSUtil.gClassnameToAllMethodsDict")
      FridaiOSUtil.gClassnameToAllMethodsDict[classname] = allMethods
    }

    return allMethods
  }

  static find_symbol_from_address(modulePath, addr){
    var symbol = "???"
    var modulePathAddr = modulePath + "|" + addr

    var needAddToCache = false

    if (isUseCache){
      if (modulePathAddr in FridaiOSUtil.gModulePathAddrToSymbolDict){
        symbol = FridaiOSUtil.gModulePathAddrToSymbolDict[modulePathAddr]
        // XLOG("Found: modulePathAddr=" + modulePathAddr + " in FridaiOSUtil.gModulePathAddrToSymbolDict, symbol=" + symbol)
        return symbol
      } else {
        needAddToCache = true
      }
    }

    var frameAddr = addr
    var theDis = 0xffffffffffffffff
    var tmpDis = 0
    var theClass = "None"
    var theMethodName = "None"
    var theMethodType = "-"
    var theMethodIMP = 0
    
    var allClassInfo = {}

    var allClass = FridaiOSUtil.get_all_objc_class(modulePath)
    
    for(var i = 0, len = allClass.length; i < len; i++){
      var curClassName = allClass[i]
      // var mInfo = get_all_class_method(curClassName)
      var mInfo = FridaiOSUtil.get_all_class_methods(curClassName)
      
      var objms = mInfo[0]
      for(var j = 0, olen = objms.length; j < olen; j++){
        var mname = objms[j][0]
        var mIMP = objms[j][1]
        if(frameAddr >= mIMP){
          var tmpDis = frameAddr-mIMP
          if(tmpDis < theDis){
            theDis = tmpDis
            theClass = curClassName
            theMethodName = mname
            theMethodIMP = mIMP
            theMethodType = "-"
          }
        }
      }

      var metams = mInfo[1]
      for(var k = 0, mlen = metams.length; k < mlen; k++){
        var mname = metams[k][0]
        var mIMP = metams[k][1]
        if(frameAddr >= mIMP){
          var tmpDis = frameAddr-mIMP
          if(tmpDis < theDis){
            theDis = tmpDis
            theClass = curClassName
            theMethodName = mname
            theMethodIMP = mIMP
            theMethodType = "+"
          }
        }
      }
    }

    symbol = theMethodType+"["+theClass+" "+theMethodName+"]"

    if(symbol.indexOf(".cxx") != -1){
        symbol = "maybe C function?"
    }
    
    // if distance > 3000, maybe a c function
    if(theDis > 3000){
        symbol = "maybe C function? symbol:" + symbol
    }

    if (needAddToCache){
      // XLOG("Add: modulePathAddr=" + modulePathAddr + ", symbol=" + symbol + " into cache FridaiOSUtil.gModulePathAddrToSymbolDict")
      FridaiOSUtil.gModulePathAddrToSymbolDict[modulePathAddr] = symbol
    }

    return symbol
  }

  static generateFunctionCallStackList(context){
    var functionCallList = new Array()

    var mainPath = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    // XLOG("mainPath=" + mainPath)
    var mainModuleName = FridaiOSUtil.getExecFileName(mainPath)
    // XLOG("mainModuleName=" + mainModuleName)

    var backtrace = Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
    for (var i = 0;i < backtrace.length;i ++)
    {
      // curStackFrame=0x10a1d1910 SharedModules!WAGetWCIHttpImpl
      // curStackFrame=0x1070f0cb4 !0x2304cb4 (0x102304cb4)
      // curStackFrame=0x1944a9614 /System/Library/Frameworks/CFNetwork.framework/CFNetwork!+[NSURLRequest requestWithURL:]
      var curStackFrame = backtrace[i] + ''
      // XLOG("curStackFrame=" + curStackFrame)

      // var curSym = curStackFrame.split("!")[1]
      var stackFrameSplittedArr = curStackFrame.split("!")
      var curAddrAndModuleStr = stackFrameSplittedArr[0]
      // XLOG("curAddrAndModuleStr=" + curAddrAndModuleStr)
      var curSym = stackFrameSplittedArr[1]
      // XLOG("curSym=" + curSym)

      // var curAddr = curStackFrame.split("!")[0].split(" ")[0]
      var curAddrAndModuleArr = curAddrAndModuleStr.split(" ")
      // XLOG("curAddrAndModuleArr=" + curAddrAndModuleArr)
      var curAddr = curAddrAndModuleArr[0]
      // XLOG("curAddr=" + curAddr)
      // var curModuleName = curStackFrame.split("!")[0].split(" ")[1]
      var curModuleName = curAddrAndModuleArr[1]
      // XLOG("curModuleName=" + curModuleName)
      
      var moduleInfoDict = FridaiOSUtil.get_info_form_address(curAddr);
      // XLOG("moduleInfoDict=" + toJsonStr(moduleInfoDict))

      var curModulePath = moduleInfoDict["fileName"]
      // XLOG("curModulePath=" + curModulePath)
      var fileAddress = moduleInfoDict["fileAddress"]
      // XLOG("fileAddress=" + fileAddress)
      var symbolName = moduleInfoDict["symbolName"]
      // XLOG("symbolName=" + symbolName)
      var symbolAddress = moduleInfoDict["symbolAddress"]
      // XLOG("symbolAddress=" + symbolAddress)

      // skip frida call stack
      if(!curModulePath){
        XLOG("! Omit for empty module path, parsed from curAddr=" + curAddr + ", moduleInfoDict=" + moduleInfoDict)
        continue
      }

      // var fileAddr = curAddr - get_image_vm_slide(curModulePath);
      var curModuleSlide = FridaiOSUtil.get_image_vm_slide(curModulePath)
      // XLOG("curModuleSlide=" + curModuleSlide)
      var fileAddr = curAddr - curModuleSlide
      // XLOG("fileAddr=" + fileAddr)

      // is the image in app dir?
      if (curModulePath.indexOf(mainModuleName) != -1 ) {
        curSym = FridaiOSUtil.find_symbol_from_address(curModulePath, curAddr)
        // XLOG("new curSym=" + curSym)
      }

      var curFunctionCallDict = {
        "curModulePath": curModulePath,
        "curAddr": curAddr,
        "fileAddr": fileAddr,
        "curSym": curSym,
      }
      functionCallList.push(curFunctionCallDict)
    }

    return functionCallList
  }

  static generateFunctionCallStackStr(functionCallList){
    var functionCallStackStr = "------------------------ printFunctionCallStack_symbol  ------------------------"
    functionCallStackStr += "\n"
    for (var i = 0;i < functionCallList.length; i++){
      var curFunctionCallDict = functionCallList[i]
      var curModulePath = curFunctionCallDict["curModulePath"]
      var curAddr = curFunctionCallDict["curAddr"]
      var fileAddr = curFunctionCallDict["fileAddr"]
      var curSym = curFunctionCallDict["curSym"]
      var executableFilename = FridaiOSUtil.getExecFileName(curModulePath)
      let execMaxWidth = 20
      // let execMaxWidth = 25
      var curFuncCallStr = FridaiOSUtil.format(i, 4)+FridaiOSUtil.format(executableFilename, execMaxWidth)+"mem:"+FridaiOSUtil.format(ptr(curAddr),13)+"file:"+FridaiOSUtil.format(ptr(fileAddr),13)+FridaiOSUtil.format(curSym,80)
      functionCallStackStr += curFuncCallStr + "\n"
    }
    functionCallStackStr += "--------------------------------------------------------------------------------"
    return functionCallStackStr
  }

  static printFunctionCallStack_symbol(context){
    var functionCallStackList = FridaiOSUtil.generateFunctionCallStackList(context)
    var functionCallStackStr = FridaiOSUtil.generateFunctionCallStackStr(functionCallStackList)
    console.log(functionCallStackStr)
    return functionCallStackStr
  }

}
