/*
 * Javascript string realted functions
 * 
 * Author: Crifan Li
 * Updated: 20180808
 * 
 */

// extract single sub string from full string
// eg: extract '012345678912345' from 'www.ucows.cn/qr?id=012345678912345'
export function  extractSingleStr(curStr, pattern, flags='i') {
  let extractedStr = null;

  let rePattern = new RegExp(pattern, flags);
  console.log(rePattern);

  let matches = rePattern.exec(curStr);
  console.log(matches);

  if (matches) {
    extractedStr = matches[0];
    console.log(extractedStr);
  }

  if (extractedStr === null) {
    extractedStr = "";
  }

  console.log(`curStr=${curStr}, pattern=${pattern}, flags=${flags} -> extractedStr=${extractedStr}`);

  return extractedStr;
}

// let capitalizedStr = originStr.capitalize()
// 'hello' -> 'Hello'
String.prototype.capitalize = function() {
  return this.charAt(0).toUpperCase() + this.slice(1);
}

// add String.format support
if (!String.format) {
  String.format = function(format) {
    var args = Array.prototype.slice.call(arguments, 1);
    return format.replace(/{(\d+)}/g, function(match, number) { 
      return typeof args[number] != 'undefined'
        ? args[number] 
        : match
      ;
    });
  };
}
// console.debug("=== Test String format:")
// var int1 = 123
// var str2 = "abc"
// var float3 = 4.56
// var formatedStr = String.format("int1={0}\nstr2={1}\tfloat3={2}", int1, str2, float3);
// console.log("formatedStr=%s", formatedStr)
// formatedStr=int1=123
// str2=abc	float3=4.56