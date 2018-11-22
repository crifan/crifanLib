/*
 * Javascript type check realted functions
 * 
 * Author: Crifan Li
 * Updated: 20181122
 * 
 */

export function isEmptyObj(obj) {
// function isEmptyObj(obj) {
    var isEmpty = false
    if (obj === undefined){
      isEmpty = true
    } else {
      isEmpty = (Object.keys(obj).length === 0)
    }
    return isEmpty
  }
  // console.debug("=== test empty object ===")
  // var emptyObj = {}
  // var undefinedObj = undefined
  // console.log("emptyObj isEmpty=", isEmptyObj(emptyObj)) // true
  // console.log("undefinedObj isEmpty=", isEmptyObj(undefinedObj)) // true
  

export function isString(curValue) {
  const isStr = (typeof curValue === 'string' || curValue instanceof String)
  return isStr
}

export function isNumber(curValue) {
  const isNum = (typeof curValue === 'number' || curValue instanceof Number)
  return isNum
}

export function isBoolean(curValue) {
  const isBool = (typeof curValue === 'boolean' || curValue instanceof Boolean)
  return isBool
}
