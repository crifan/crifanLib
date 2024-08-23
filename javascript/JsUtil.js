/*
	File: JsUtil.js
	Function: crifan's common Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/JsUtil.js
	Updated: 20240823
*/

// pure JavaScript utils
class JsUtil {

  constructor() {
    console.log("JsUtil constructor")
  }

  static {
  }

  static logStr(curStr){
    let delimiterStr = "--------------------"
    console.log(delimiterStr + " " + curStr + " " + delimiterStr)
  }

  // convert Object(dict/list/...) to JSON string
  // function toJsonStr(curObj, singleLine=false, space=2){
  static toJsonStr(curObj, singleLine=false, space=2){
    // console.log("toJsonStr: singleLine=" + singleLine)
    // var jsonStr = JSON.stringify(curObj, null, 2)
    var jsonStr = JSON.stringify(curObj, null, space)
    if(singleLine) {
      // jsonStr = jsonStr.replace(/\\n/g, '')
      jsonStr = jsonStr.replace(/\n/g, '')
    }
    return jsonStr
    // return curObj.toString()
  }

  // byte decimaal to byte hex
  // eg:
  //    8 => 8
  //    -60 => c4
  // function byteDecimalToByteHex(byteDecimal) {
  static byteDecimalToByteHex(byteDecimal) {
    // var digitCount = 6
    var digitCount = 2
    var minusDigitCount = 0 - digitCount
    // return (byteDecimal + Math.pow(16, 6)).toString(16).substr(-6)
    // var hexStr = (byteDecimal + Math.pow(16, 2)).toString(16).substr(-2)
    // return (byteDecimal + Math.pow(16, digitCount)).toString(16).substr(minusDigitCount)
    var hexStr = (byteDecimal + Math.pow(16, digitCount)).toString(16).substr(minusDigitCount)
    // console.log("typeof hexStr=" + (typeof hexStr))
    // console.log("hexStr=" + hexStr)
    var hexValue = parseInt(hexStr, 16)
    // console.log("typeof hexValue=" + (typeof hexValue))
    // console.log("hexValue=" + hexValue)
    return hexValue
  }

  // check is js string
  static isJsStr(curObj){
    // console.log("curObj=" + curObj)
    var curObjType = (typeof curObj)
    // console.log("curObjType=" + curObjType)
    var isStr = curObjType === "string"
    // console.log("isStr=" + isStr)
    return isStr
  }

}