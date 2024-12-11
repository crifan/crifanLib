/*
	File: JsUtil.js
	Function: crifan's common Javascript related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/JsUtil.js
	Updated: 20241211
*/

// pure JavaScript utils
class JsUtil {

  constructor() {
    console.log("JsUtil constructor")
  }

  static {
  }

  /*---------- Number(Int) ----------*/

  static intToHexStr(intValue, prefix="0x"){
    var hexStr = prefix + intValue.toString(16)
    return hexStr
  }

  /*---------- Log ----------*/

  // Generate single line log string
  // input: logStr="Called: -[NSURLRequest initWithURL:]"
  // output: "=============================== Called: -[NSURLRequest initWithURL:] ==============================="
  static generateLineStr(logStr, isWithSpace=true, delimiterChar="=", lineWidth=80){
    // console.log("logStr=" + logStr, ", isWithSpace=" + isWithSpace + ", delimiterChar=" + delimiterChar + ", lineWidth=" + lineWidth)
    var lineStr = ""

    var realLogStr = ""
    if (isWithSpace) {
      realLogStr = " " + logStr + " "
    } else {
      realLogStr = logStr
    }

    var realLogStrLen = realLogStr.length
    if ((realLogStrLen % 2) > 0){
      realLogStr += " "
      realLogStrLen = realLogStr.length
    }

    var leftRightPaddingStr = ""
    var paddingLen = lineWidth - realLogStrLen
    if (paddingLen > 0) {
      var leftRightPaddingLen = paddingLen / 2
      leftRightPaddingStr = JsUtil.times(delimiterChar, leftRightPaddingLen)
    }

    lineStr = leftRightPaddingStr + realLogStr + leftRightPaddingStr

    // console.log("lineStr:\n" + lineStr)
    return lineStr
  }

  static logStr(curStr, isWithSpace=true, delimiterChar="=", lineWidth=80){
    // let delimiterStr = "--------------------"
    // console.log(delimiterStr + " " + curStr + " " + delimiterChar)
    var lineStr = JsUtil.generateLineStr(curStr, isWithSpace, delimiterChar, lineWidth)
    console.log(lineStr)
  }


  /*---------- Object: Dict/List/... ----------*/

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

  /*---------- List ----------*/

  // check whether is item inside the list
  // eg: curItem="abc", curList=["abc", "def"] => true
  static isItemInList(curItem, curList){
    // method1:
    return curList.includes(curItem)
    // // method2:
    // return curList.indexOf(curItem) > -1
  }

  static sortByKey(curList, keyName){
    if (null != curList){
      curList.sort(function(objA, objB) {
        var valueA = objA[keyName]
        var valueB = objB[keyName]
        var valudDiff = valueA - valueB
        // console.log("valueA=" + valueA + ", valueB=" + valueB + " -> valudDiff=" + valudDiff)
        return valudDiff
      })  
    }
  }

  /*---------- String ----------*/

  /** Function that count occurrences of a substring in a string;
   * @param {String} string               The string
   * @param {String} subString            The sub string to search for
   * @param {Boolean} [allowOverlapping]  Optional. (Default:false)
   *
   * @author Vitim.us https://gist.github.com/victornpb/7736865
   * @see Unit Test https://jsfiddle.net/Victornpb/5axuh96u/
   * @see https://stackoverflow.com/a/7924240/938822
   */
  static occurrences(string, subString, allowOverlapping) {
    // console.log("string=" + string + ",subString=" + subString + ", allowOverlapping=" + allowOverlapping)
    string += "";
    subString += "";
    if (subString.length <= 0) return (string.length + 1);

    var n = 0,
      pos = 0,
      step = allowOverlapping ? 1 : subString.length;

    while (true) {
      pos = string.indexOf(subString, pos);
      // console.log("pos=" + pos)
      if (pos >= 0) {
        ++n;
        pos += step;
      } else break;
    }

    return n;
  }

  // String multiple
  // eg: str="=", num=5 => "====="
  static times(str, num){
    return new Array(num + 1).join(str)
  }

  // check string is empty or null
  static strIsEmpty(curStr){
    var isNull = null == curStr
    var isEmp = "" === curStr
    return isNull || isEmp
  }

  /*---------- Byte ----------*/

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

  /*---------- Object ----------*/

  // check is js string
  static isJsStr(curObj){
    // console.log("curObj=" + curObj)
    var curObjType = (typeof curObj)
    // console.log("curObjType=" + curObjType)
    var isStr = curObjType === "string"
    // console.log("isStr=" + isStr)
    return isStr
  }

  /*---------- Pointer ----------*/

  // check pointer is valid or not
  // example
  // 		0x103e79560 => true
  // 		0xc => false
  static isValidPointer(curPtr){
    let MinValidPointer = 0x10000
    var isValid = curPtr > MinValidPointer
    // console.log("curPtr=" + curPtr, " -> isValid=" + isValid)
    return isValid
  }

}