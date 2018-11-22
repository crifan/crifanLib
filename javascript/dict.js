/*
 * Javascript Dict related functions
 * 
 * Author: Crifan Li
 * Updated: 20181122
 * 
 */


// input: {book_id: "5bd7bd51bfaa44fe2c737c78"}, "book_id"
// output: [true, "5bd7bd51bfaa44fe2c737c78"]
function getValueFromDict(dictObj, keyName){
    console.log("getValueFromDict: dictObj=%o, keyName=%s", dictObj, keyName)
  
    var getOk = false
    var gotValue = undefined
    if (dictObj) {
        var dictKeys = Object.keys(dictObj)
        console.log("dictKeys=%o", dictKeys)
        if (dictKeys.includes(keyName)){
          getOk = true
          gotValue = dictObj[keyName]
        }
    }
  
    console.log("getOk=%s, gotValue=%s", getOk, gotValue)
    return [getOk, gotValue]
}
