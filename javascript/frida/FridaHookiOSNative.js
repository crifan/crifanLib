/*
	File: FridaHookiOSNative.js
	Function: crifan's Frida hook iOS native related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookiOSNative.js
	Updated: 20241122
*/

// Frida hook iOS native functions
class FridaHookiOSNative {
  static objc_getClass = null
  static objc_getMetaClass = null
  static objc_copyClassNamesForImage = null
  static class_copyMethodList = null
  static method_getName = null
  static _dyld_image_count = null
  static _dyld_get_image_name = null
  static _dyld_get_image_vmaddr_slide = null

  constructor() {
    console.log("FridaHookiOSNative constructor")
  }

  static {
    if (FridaUtil.isiOS()){
      FridaHookiOSNative.objc_getClass = FridaHookiOSNative.genNativeFunc_objc_getClass()
      console.log("FridaHookiOSNative.objc_getClass=" + FridaHookiOSNative.objc_getClass)
  
      FridaHookiOSNative.objc_getMetaClass = FridaHookiOSNative.genNativeFunc_objc_getMetaClass()
      console.log("FridaHookiOSNative.objc_getMetaClass=" + FridaHookiOSNative.objc_getMetaClass)
  
      FridaHookiOSNative.objc_copyClassNamesForImage = FridaHookiOSNative.genNativeFunc_objc_copyClassNamesForImage()
      console.log("FridaHookiOSNative.objc_copyClassNamesForImage=" + FridaHookiOSNative.objc_copyClassNamesForImage)
  
      FridaHookiOSNative.class_copyMethodList = FridaHookiOSNative.genNativeFunc_class_copyMethodList()
      console.log("FridaHookiOSNative.class_copyMethodList=" + FridaHookiOSNative.class_copyMethodList)
  
      FridaHookiOSNative.method_getName = FridaHookiOSNative.genNativeFunc_method_getName()
      console.log("FridaHookiOSNative.method_getName=" + FridaHookiOSNative.method_getName)
  
      FridaHookiOSNative._dyld_image_count = FridaHookiOSNative.genNativeFunc__dyld_image_count()
      console.log("FridaHookiOSNative._dyld_image_count=" + FridaHookiOSNative._dyld_image_count)
  
      FridaHookiOSNative._dyld_get_image_name = FridaHookiOSNative.genNativeFunc__dyld_get_image_name()
      console.log("FridaHookiOSNative._dyld_get_image_name=" + FridaHookiOSNative._dyld_get_image_name)
  
      FridaHookiOSNative._dyld_get_image_vmaddr_slide = FridaHookiOSNative.genNativeFunc__dyld_get_image_vmaddr_slide()
      console.log("FridaHookiOSNative._dyld_get_image_vmaddr_slide=" + FridaHookiOSNative._dyld_get_image_vmaddr_slide)
    } else {
      console.warn("FridaHookiOSNative: Non iOS platfrom, no need init iOS related")
    }
  }

  static genNativeFunc_objc_getClass(){
    var newNativeFunc_objc_getClass = null
    var origNativeFunc_objc_getClass = Module.findExportByName(null, 'objc_getClass')
    // console.log("origNativeFunc_objc_getClass=" + origNativeFunc_objc_getClass)
    // id objc_getClass(const char *name);
    if (null != origNativeFunc_objc_getClass) {
      newNativeFunc_objc_getClass = new NativeFunction(
        origNativeFunc_objc_getClass,
        'pointer',
        ['pointer']
      )  
    }
    // console.log("newNativeFunc_objc_getClass=" + newNativeFunc_objc_getClass)
    return newNativeFunc_objc_getClass
  }

  static genNativeFunc_class_copyMethodList(){
    var newNativeFunc_class_copyMethodList = null
    var origNativeFunc_class_copyMethodList = Module.findExportByName(null, 'class_copyMethodList')
    if (null != origNativeFunc_class_copyMethodList) {
      newNativeFunc_class_copyMethodList = new NativeFunction(
        origNativeFunc_class_copyMethodList,
        'pointer',
        ['pointer', 'pointer']
      )
    }
    return newNativeFunc_class_copyMethodList
  }

  static genNativeFunc_objc_getMetaClass(){
    var newNativeFunc_objc_getMetaClass = null
    var origNativeFunc_objc_getMetaClass = Module.findExportByName(null, 'objc_getMetaClass')
    if (null != origNativeFunc_objc_getMetaClass) {
      newNativeFunc_objc_getMetaClass = new NativeFunction(
        origNativeFunc_objc_getMetaClass,
        'pointer',
        ['pointer']
      )  
    }
    return newNativeFunc_objc_getMetaClass
  }

  static genNativeFunc_objc_copyClassNamesForImage(){
    // const char * objc_copyClassNamesForImage(const char *image, unsigned int *outCount)
    var newNativeFunc_objc_copyClassNamesForImage = null
    var origNativeFunc_objc_copyClassNamesForImage = Module.findExportByName(null, 'objc_copyClassNamesForImage')
    if (null != origNativeFunc_objc_copyClassNamesForImage) {
      newNativeFunc_objc_copyClassNamesForImage = new NativeFunction(
        origNativeFunc_objc_copyClassNamesForImage,
        'pointer',
        ['pointer', 'pointer']
      )
    }
    return newNativeFunc_objc_copyClassNamesForImage
  }

  static genNativeFunc_method_getName(){
    var newNativeFunc_method_getName = null
    var origNativeFunc_method_getName = Module.findExportByName(null, 'method_getName')
    if (null != origNativeFunc_method_getName) {
      newNativeFunc_method_getName = new NativeFunction(
        origNativeFunc_method_getName,
        'pointer',
        ['pointer']
      )
    }
    return newNativeFunc_method_getName
  }

  static genNativeFunc__dyld_image_count(){
    // uint32_t  _dyld_image_count(void)
    var newNativeFunc__dyld_image_count = null
    var origNativeFunc__dyld_image_count = Module.findExportByName(null, '_dyld_image_count')
    if (null != origNativeFunc__dyld_image_count) {
      newNativeFunc__dyld_image_count = new NativeFunction(
        origNativeFunc__dyld_image_count,
        'uint32',
        []
      )  
    }
    return newNativeFunc__dyld_image_count
  }

  static genNativeFunc__dyld_get_image_name(){
    // const char*  _dyld_get_image_name(uint32_t image_index)
    var newNativeFunc__dyld_get_image_name = null
    var origNativeFunc__dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name')
    if (null != origNativeFunc__dyld_get_image_name) {
      newNativeFunc__dyld_get_image_name = new NativeFunction(
        origNativeFunc__dyld_get_image_name,
        'pointer',
        ['uint32']
      )  
    }
    return newNativeFunc__dyld_get_image_name
  }

  static genNativeFunc__dyld_get_image_vmaddr_slide(){
    // intptr_t   _dyld_get_image_vmaddr_slide(uint32_t image_index)
    var newNativeFunc__dyld_get_image_vmaddr_slide = null
    var origNativeFunc__dyld_get_image_vmaddr_slide = Module.findExportByName(null, '_dyld_get_image_vmaddr_slide')
    if (null != origNativeFunc__dyld_get_image_vmaddr_slide) {
      newNativeFunc__dyld_get_image_vmaddr_slide = new NativeFunction(
        origNativeFunc__dyld_get_image_vmaddr_slide,
        'pointer',
        ['uint32']
      )
    }
    return newNativeFunc__dyld_get_image_vmaddr_slide
  }

}
