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


function redirectToUrl(baseUrl, queryParaDict={}){
    console.log("redirectToUrl: baseUrl=%s, queryParaDict=%o", baseUrl, queryParaDict)
  
    var encodedQueryStr = ""
    if (queryParaDict){
        encodedQueryStr = encodeQueryDict(queryParaDict)
    }
    console.log("encodedQueryStr=", encodedQueryStr)
  
    var fullUrl = baseUrl
    if (encodedQueryStr) {
        fullUrl += "?" + encodedQueryStr
    }
    // console.log("fullUrl=", fullUrl)
    console.log("Now redirect to url: %s", fullUrl)
    window.location = fullUrl
  }
  
  // from: file:///xxx/StorybookQueryWeb/index.html?q=&tag=Individuality&difficulty=7
  // got: /xxx/StorybookQueryWeb/index.html
  function getCurUrlPath(){
    // var curUrl = window.location.href.substring(window.location.href.lastIndexOf('/') + 1).split("?")[0]
    // console.log("curUrl=%o", curUrl)
    // locationHref="file:///xxx/StorybookQueryWeb/index.html?q=&tag=Individuality&difficulty=7"
    var locationPathname = window.location.pathname
    console.log("locationPathname=%o", locationPathname)
    return locationPathname
  }
  
  
  // clear query string in url: index.html?q=&tag=Individuality&difficulty=7
  // to : index.html
  function clearQueryStrInUrl(){
    // var locationHref = window.location.href
    // console.log("locationHref=%s", locationHref)
    var curUrl = getCurUrlPath()
    console.log("curUrl=%s", curUrl)
    var curTitle = document.title
    console.log("curTitle=%s", curTitle)
    // window.history.pushState({"q": ""}, curTitle, curUrl)
    window.history.pushState({}, curTitle, curUrl)
  }
  