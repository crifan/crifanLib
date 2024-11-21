/*
	File: FridaHookAndroidNative.js
	Function: crifan's Frida hook Android native related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookAndroidNative.js
	Updated: 20241121
*/

// Frida hook Android native functions
class FridaHookAndroidNative {
  constructor() {
    console.log("FridaHookAndroidNative constructor")
  }

  static JNI_OnLoad(libraryName) {
    const funcSym = "JNI_OnLoad"
    const funcPtr = Module.findExportByName(libraryName, funcSym)
    console.log("[+] Hooking " + funcSym + ", funcPtr=" + funcPtr)
    // jint JNI_OnLoad(JavaVM *vm, void *reserved)
    if (null != funcPtr){
      var funcHook = Interceptor.attach(funcPtr, {
        onEnter: function (args) {
          const vm = args[0]
          const reserved = args[1]
          console.log("[+] " + funcSym + "(" + vm + ", " + reserved + ") called")
        },
        onLeave: function (retval) {
          console.log("[+]\t= " + retval)
        }
      })  
    }
  }

}