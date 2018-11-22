/*
 * Javascript URL/http related functions
 * 
 * Author: Crifan Li
 * Updated: 20181122
 * 
 */


// input: q=&tag=Shapes%20and%20Sizes&difficulty=2
// output: {q: "", tag: "Shapes and Sizes", difficulty: "2"}
function decodeQueryStr(encodedQueryStr) {
    console.log("decodeQueryStr: encodedQueryStr=%s", encodedQueryStr)
    var decodedQueryDict = {}
  
    if (encodedQueryStr){
        var keyValuePairList = encodedQueryStr.split('&')
        console.log("keyValuePairList=%o", keyValuePairList)
  
        for (keyValuePair of keyValuePairList){
            console.log("keyValuePair=%s", keyValuePair)
            var keyValueList = keyValuePair.split("=")
            console.log("keyValueList=%o", keyValueList)
            var curKey = keyValueList[0]
            console.log("curKey=%s", curKey)
            if (curKey){
                var curValue = keyValueList[1]
                console.log("curValue=%s", curValue)
                var decodedKey = decodeURIComponent(curKey)
                var decodedValue = decodeURIComponent(curValue)
                console.log("decodedKey=%s, decodedValue=%s", decodedKey, decodedValue)
                
                decodedQueryDict[decodedKey] = decodedValue
            }
        }
    }
  
    console.log("decodedQueryDict=%o", decodedQueryDict)
    return decodedQueryDict
}
  
  
  // input:  {q: "", tag: "Shapes and Sizes", difficulty: 2}
  // output:  q=&tag=Shapes%20and%20Sizes&difficulty=2
  function encodeQueryDict(queryDict){
    console.log("encodeQueryDict: queryDict=%o", queryDict)
    var encodedQueryStr = ""
    if (queryDict){
        var encodedKeyValueStrList = []
  
        var keyValueList = Object.entries(queryDict)
        console.log("keyValueList=%o", keyValueList)
        for (const [ eachKey, eachValue ] of keyValueList){
            console.log("eachKey=%s, eachValue=%s", eachKey, eachValue)
            var encodedKey = encodeURIComponent(eachKey)
            console.log("encodedKey=%o", encodedKey)
            var encodedValue = encodeURIComponent(eachValue)
            console.log("encodedValue=%o", encodedValue)
            var encodedKeyValueStr = `${encodedKey}=${encodedValue}`
            console.log("encodedKeyValueStr=%o", encodedKeyValueStr)
            encodedKeyValueStrList.push(encodedKeyValueStr)
        }
  
        console.log("encodedKeyValueStrList=%o", encodedKeyValueStrList)
        if (encodedKeyValueStrList.length > 0){
            encodedQueryStr = encodedKeyValueStrList.join("&")
        }
    }
  
    console.log("encodedQueryStr=%o", encodedQueryStr)
    return encodedQueryStr
}
  

// current url: http://xxx/index.html?q=&tag=Problem%20Solving&difficulty=20
// extract out: q=&tag=Problem%20Solving&difficulty=20
function getCurQueryStr(){
    console.log("getCurQueryStr")
    var curQuerySearch = window.location.search.substring(1)
    console.log("curQuerySearch=%s", curQuerySearch)
    return curQuerySearch
}

  // input: None
//    current url is: http://xxx/index.html?q=&tag=Lost%20and%20Found&difficulty=20
// output: {q: "", tag: "Lost and Found", difficulty: "20"}
function getCurQueryDict(){
    console.log("getCurQueryDict")
    var decodedQueryDict = decodeQueryStr(getCurQueryStr())
    console.log("decodedQueryDict=%o", decodedQueryDict)
    return decodedQueryDict
}

// function: get query value from current query search string via query key
// input: "book_id"
//    current url: http://xxx/book_detail.html?book_id=5bd7bd3ebfaa44fe2c737678
// output: [true, "5bd7bd51bfaa44fe2c737c78"]
// exmaple:
// var getOk, curBookId
// [getOk, curBookId] = getQueryValueFromCurSearch("book_id")
function getQueryValueFromCurSearch(queryKey){
    console.log("getQueryValueFromCurSearch: queryKey=%s", queryKey)
    var currentQueryDict = getCurQueryDict()
    return getValueFromDict(currentQueryDict, queryKey)
}
