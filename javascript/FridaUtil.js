/*
	File: FridaUtil.js
	Function: crifan's common Frida Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/FridaUtil.js
	Updated: 20240823
*/

// Frida/Android/Java related utils
class FridaUtil {
  static curThrowableCls = Java.use("java.lang.Throwable")

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  static {
    // console.log("this.curThrowableCls=" + this.curThrowableCls)
    console.log("FridaUtil.curThrowableCls=" + FridaUtil.curThrowableCls)

    FridaUtil.JavaArray = Java.use('java.lang.reflect.Array')
    console.log("FridaUtil.JavaArray=" + FridaUtil.JavaArray)
    FridaUtil.JavaArrays = Java.use("java.util.Arrays")
    console.log("FridaUtil.JavaArrays=" + FridaUtil.JavaArrays)
    FridaUtil.JavaArrayList = Java.use('java.util.ArrayList')
    console.log("FridaUtil.JavaArrayList=" + FridaUtil.JavaArrayList)

    FridaUtil.JavaByteArr = Java.use("[B")
    console.log("FridaUtil.JavaByteArr=" + FridaUtil.JavaByteArr)
    // var JavaObjArr = Java.use("[Ljava.lang.Object")
    FridaUtil.JavaObjArr = Java.use("[Ljava.lang.Object;")
    console.log("FridaUtil.JavaObjArr=" + FridaUtil.JavaObjArr)
  }

  // constructor(curThrowableCls) {
  constructor() {
    console.log("FridaUtil constructor")
    // this.curThrowableCls = curThrowableCls
    // console.log("this.curThrowableCls=" + this.curThrowableCls)
  }

  // Frida pointer to UTF-8 string
  static ptrToUtf8Str(curPtr){
    var curUtf8Str = curPtr.readUtf8String()
    // console.log("curUtf8Str=" + curUtf8Str)
    return curUtf8Str
  }

  // Frida pointer to C string
  static ptrToCStr(curPtr){
    var curCStr = curPtr.readCString()
    // console.log("curCStr=" + curCStr)
    return curCStr
  }

  // get java class name
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  static getJclassName(clazz){
    var env = Java.vm.tryGetEnv()
    // console.log("env=" + env) // env=[object Object]
    var className = env.getClassName(clazz)
    // console.log("className=" + className)
    return className
  }

  static findSymbolFromLib(soLibName, callback_isFound) {
    console.log("soLibName=" + soLibName + ", callback_isFound=" + callback_isFound)
  
    var foundSymbolList = []
    let libSymbolList = Module.enumerateSymbolsSync(soLibName)
    // console.log("libSymbolList=" + libSymbolList)
    for (let i = 0; i < libSymbolList.length; i++) {
        var curSymbol = libSymbolList[i]
        // console.log("[" + i  + "] curSymbol=" + curSymbol)
  
        var symbolName = curSymbol.name
        // console.log("[" + i  + "] symbolName=" + symbolName)

        // var isFound = callback_isFound(symbolName)
        var isFound = callback_isFound(curSymbol)
        // console.log("isFound=" + isFound)
  
        if (isFound) {
          console.log("[" + i  + "] curSymbol=" + curSymbol)

          var symbolAddr = curSymbol.address
          // console.log("symbolAddr=" + symbolAddr)

          foundSymbolList.push(curSymbol)
          console.log("+++ Found smbol: addr=" + symbolAddr + ", name=" + symbolName)
        }
    }
  
    console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
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
        // console.log("args=" + args)
  
        var libFullPath = args[0].readCString()
        // console.log("libFullPath=" + libFullPath)
        // var flags = args[1]
        // var info = args[2]
        // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        // if(libraryName === libFullPath){
        if(libFullPath.includes(libraryName)){
          console.log("+++ Loaded " + libraryName)
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

  static printFunctionCallStack_addr(curContext){
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    console.log('Stack:\n' +
      Thread.backtrace(curContext, backtracerType)
      .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }

  // java byte array to js byte array
  static javaByteArrToJsByteArr(javaByteArr){
    // var javaByteArrLen = javaByteArr.length
    // console.log("javaByteArrLen=" + javaByteArrLen) // javaByteArrLen=undefined
    var javaByteArrGotLen = FridaUtil.JavaArray.getLength(javaByteArr)
    console.log("javaByteArrGotLen=" + javaByteArrGotLen) // javaByteArrGotLen=8498
    var jsByteArr = new Array()
    // console.log("jsByteArr=" + jsByteArr)
    for(var i = 0; i < javaByteArrGotLen; ++i) {
      // jsByteArr[i] = javaByteArr[i]
      var curByte = FridaUtil.JavaArray.get(javaByteArr, i)
      // console.log("curByte=" + curByte)
      jsByteArr[i] = curByte
    }
    // console.log("jsByteArr=" + jsByteArr)
    return jsByteArr;
  }

  // function getJavaClassName(curObj){
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

  // function isJavaClass(curObj, expectedClassName){
  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  } 

  // convert (Java) map (java.util.HashMap) key=value string list
  // function mapToKeyValueStrList(curMap){
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
  // function mapToStr(curMap){
  static mapToStr(curMap){
    // return JSON.stringify(curMap, (key, value) => (value instanceof Map ? [...value] : value));
    // var keyValStrList = this.mapToKeyValueStrList(curMap)
    var keyValStrList = FridaUtil.mapToKeyValueStrList(curMap)
    // console.log("keyValStrList=" + keyValStrList)
    var mapStr = keyValStrList.join(", ")
    var mapStr = `[${mapStr}]`
    // console.log("mapStr=" + mapStr)
    return mapStr
  }

  // function describeJavaClass(className) {
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
  // function enumMethods(targetClass)
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
  // function enumProperties(targetClass)
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
  // function printClassAllMethodsFields(javaClassName){
  static printClassAllMethodsFields(javaClassName) {
    console.log("==========" + "Class: " + javaClassName + " ==========")

    console.log("-----" + "All Properties" + "-----")
    // var allProperties = enumProperties(javaClassName)
    // var allProperties = this.enumProperties(javaClassName)
    var allProperties = FridaUtil.enumProperties(javaClassName)
    allProperties.forEach(function(singleProperty) { 
      console.log(singleProperty)
    })

    console.log("-----" + "All Methods" + "-----")
    // enumerate all methods in a class
    // var allMethods = enumMethods(javaClassName)
    // var allMethods = this.enumMethods(javaClassName)
    var allMethods = FridaUtil.enumMethods(javaClassName)
    allMethods.forEach(function(singleMethod) { 
      console.log(singleMethod)
    })

    console.log("")
  }


  // generate current stack trace string
  // function genStackStr() {
  // genStackStr() {
  static genStackStr() {
    // let newThrowable = ThrowableCls.$new()
    // let newThrowable = this.curThrowableCls.$new()
    let newThrowable = FridaUtil.curThrowableCls.$new()
    // console.log("genStackStr: newThrowable=" + newThrowable)
    var stackElements = newThrowable.getStackTrace()
    // console.log("genStackStr: stackElements=" + stackElements)
    var stackStr = "Stack: " + stackElements[0] //method//stackElements[0].getMethodName()
    for (var i = 1; i < stackElements.length; i++) {
      stackStr += "\n    at " + stackElements[i]
    }
    // stackStr = "\n\n" + stackStr
    stackStr = stackStr + "\n"
    // console.log("genStackStr: stackStr=" + stackStr)

    return stackStr
  }

  // 打印当前调用堆栈信息 print call stack
  // function printStack() {
  // printStack() {
  static printStack() {
    // var stackStr = this.genStackStr()
    var stackStr = FridaUtil.genStackStr()
    console.log(stackStr)

    // let newThrowable = ThrowableCls.$new()
    // let curLog = Java.use("android.util.Log")
    // let stackStr = curLog.getStackTraceString(newThrowable)
    // console.log("stackStr=" + stackStr)
  }

  // generate Function call string
  // function genFunctionCallStr(funcName, funcParaDict){
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

  // function printFunctionCallStr(funcName, funcParaDict){
  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }


  // print Function call and stack trace string
  // function printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=undefined){
  // printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=undefined){
  static printFunctionCallAndStack(funcName, funcParaDict, filterList=undefined){
    // console.log("filterList=" + filterList)

    var needPrint = true

    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaUtil.genFunctionCallStr(funcName, funcParaDict)

    // var stackStr = this.genStackStr()
    var stackStr = FridaUtil.genStackStr()

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
  // for some app: will crash: Process terminated
  // function findClass(pattern)
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
  // for some app: will crash: Process terminated
  // function printAllClasses(){
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
