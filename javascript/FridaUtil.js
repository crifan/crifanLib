/*
	File: FridaUtil.js
	Function: crifan's common Frida Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/FridaUtil.js
	Updated: 20240823
*/

// Frida Common Util
class FridaUtil {

  constructor() {
    console.log("FridaUtil constructor")
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

  // print function call and stack, output type is: address
  static printFunctionCallStack_addr(curContext){
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    console.log('Stack:\n' +
      Thread.backtrace(curContext, backtracerType)
      .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }

}