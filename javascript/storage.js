/*
 * Javascript storage realted functions
 * 
 * Author: Crifan Li
 * Updated: 20180802
 * 
 */

/*
  Save js object to local storage via json string
  call example: localStorage.setObj("currentUser", currentUser)
*/
Storage.prototype.setObj = function(strKey, objValue) {
  // console.log("Storage.prototype.setOb: strKey=", strKey, ", objValue=", objValue)
  const jsonStr = JSON.stringify(objValue)
  // console.log("jsonStr=", jsonStr)
  return this.setItem(strKey, jsonStr)
}

/*
  Restore js object from local storage's stored json string
  call example: restoredCurrentUser = localStorage.getObj("currentUser")
*/
Storage.prototype.getObj = function(strKey) {
  // console.log("Storage.prototype.getObj: strKey=", strKey)
  let parsedObj
  const storedStr = this.getItem(strKey)
  // console.log("storedStr=", storedStr)
  if (storedStr) {
    parsedObj = JSON.parse(storedStr)
  }
  // console.log("parsedObj=", parsedObj)
  return parsedObj
}
