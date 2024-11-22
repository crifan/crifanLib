/*
	File: FridaHookAndroidJava.js
	Function: crifan's Frida hook common Android Java related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookAndroidJava.js
	Updated: 20241122
*/

// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
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

    FridaHookAndroidJava.Settings_getInt(cls_SettingsGlobal, SettingsGlobal_getInt_crName, SettingsGlobal_getInt_crNameDef)
  }

  static SettingsSecure(SettingsSecure_getInt_crName=null, SettingsSecure_getInt_crNameDef=null) {
    var className_SettingsSecure = "android.provider.Settings$Secure"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsSecure)

    var cls_SettingsSecure = Java.use(className_SettingsSecure)
    console.log("cls_SettingsSecure=" + cls_SettingsSecure)

    FridaHookAndroidJava.Settings_getInt(cls_SettingsSecure, SettingsSecure_getInt_crName, SettingsSecure_getInt_crNameDef)
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