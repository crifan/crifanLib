/*
 * Javascript type check realted functions
 * 
 * Author: Crifan Li
 * Updated: 20180802
 * 
 */

export function isEmptyObj(obj) {
  return Object.keys(obj).length === 0
}

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
