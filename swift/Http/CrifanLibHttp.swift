//
//  CrifanLibHttp.swift
//  SalesApp
//
//  Created by licrifan on 16/6/3.
//  Copyright © 2016年 licrifan. All rights reserved.
//
//  Last Update: 2016-06-07

import UIKit
import XCGLogger
import Alamofire
import SwiftyJSON



//func getUrlRespJson_async(httpMethod:Alamofire.Method, url:String, parameters: [String : AnyObject]? = nil, headers: [String : String]? = nil, respJsonHandler: (Alamofire.Result<JSON, NSError>) -> Void) {
func getUrlRespJson_async(httpMethod:Alamofire.Method, url:String, parameters: [String : AnyObject]? = nil, headers: [String : String]? = nil, extraPara:Dictionary<String, AnyObject>?, respJsonHandler: (Alamofire.Result<JSON, NSError>, mergedAllPara:Dictionary<String, AnyObject>) -> Void) {
    gLog.info("httpMethod=\(httpMethod), url=\(url), parameters=\(parameters), headers=\(headers), extraPara=\(extraPara), respJsonHandler=\(respJsonHandler)")
    //httpMethod=POST, url=http://qapp.chinacloudapp.cn/open/code, parameters=Optional(["codetype": register, "phone": 13812345678]), headers=nil

    //merge input headers
    var currentHeaders:[String : String] = [
//        "Accept" : "application/json",
        
        //actually here not necessary to set this header
        //for when set encoding to ParameterEncoding.JSON, it will auto set this header
        "Content-Type" : "application/json",
    ]

    if let inputHeaders = headers {
        for eachKey in inputHeaders.keys {
            gLog.verbose("[\(eachKey)] = \(inputHeaders[eachKey]!)")
            currentHeaders[eachKey] = inputHeaders[eachKey]!
        }
    }
    
    var mergedExtraPara = Dictionary<String, AnyObject>()
    mergedExtraPara["httpMethod"] = httpMethod.rawValue
    mergedExtraPara["url"] = url
    mergedExtraPara["parameters"] = parameters
    mergedExtraPara["headers"] = headers
    mergedExtraPara["extraPara"] = extraPara
    
//    if extraPara != nil {
//        for eachInputParaKey in extraPara!.keys {
//            mergedExtraPara[eachInputParaKey] = extraPara![eachInputParaKey]
//        }
//    }
    
    gLog.debug("currentHeaders=\(currentHeaders)")
    //currentHeaders=["Accept": "application/json"]
    //currentHeaders=["Authorization": "Basic MTAwMDAwMTA6MTExMTEx", "Accept": "application/json"]

    Alamofire
        .request(
        httpMethod,
        url,
        parameters: parameters,
        encoding: ParameterEncoding.JSON,
        headers: currentHeaders)
        
        .responseJSON(completionHandler: { response in
        gLog.debug("request=\(response.request), response=\(response.response), statusCode=\(response.response?.statusCode), result=\(response.result)")
        gLog.verbose("data=\(response.data)")
        /*
        request=Optional(<NSMutableURLRequest: 0x7964c340> { URL: http://qapp.chinacloudapp.cn/open/code }), response=Optional(<NSHTTPURLResponse: 0x78f82160> { URL: http://qapp.chinacloudapp.cn/open/code } { status code: 200, headers {
             Connection = "keep-alive";
             "Content-Length" = 48;
             "Content-Type" = "application/json;charset=UTF-8";
             Date = "Fri, 03 Jun 2016 08:42:18 GMT";
             Server = "nginx/1.10.1";
             } }), statusCode=Optional(200), data=Optional(<7b22636f 6465223a 3230302c 226d6573 73616765 223a226f 6b222c22 64617461 223a2231 35303531 34363436 3534227d>), result=SUCCESS
         */
        
        //Note: here alwayls in MAIN UI thread !!!
        dispatchBackground_async({
            let statusCode = response.response?.statusCode ?? 0
            gLog.verbose("statusCode=\(statusCode)")
            //2016-06-15 20:32:10.878 [Verbose] [com.apple.root.background-qos] [CrifanLibHttp.swift:76] getUrlRespJson_async(_:url:parameters:headers:extraPara:respJsonHandler:) > statusCode=200

            gLog.verbose("HTTPMethod=\(response.request?.HTTPMethod), URL=\(response.request?.URL), URLString=\(response.request?.URLString), allHTTPHeaderFields=\(response.request?.allHTTPHeaderFields))")
            
            if let httpBodyData = response.request?.HTTPBody {
                let httpBodyJson = JSON(data: httpBodyData)
                gLog.verbose("httpBodyJson=\(httpBodyJson)")
                //httpBodyJson=unknown
                /*
                httpBodyJson={
                  "customer" : {
                    "followup" : 4,
                    "datafrom" : 2,
                    "phone" : "",
                    "name" : "",
                    "topComeFrom" : 0,
                    "salesId" : 10000010,
                    "testdrive" : true,
                    "comeFrom" : 0
                  },
                  "intentedcar" : {
                    "color" : "0",
                    "spec" : "0",
                    "series" : "0"
                  }
                }
                 */
            }

            switch response.result {
            case .Success(let value):
                gLog.verbose("value=\(value), value type=\(String(value.dynamicType)))")

                /*
                value={
                    code = 200;
                    data = 13812345678;
                    message = ok;
                }, value type=__NSCFDictionary)
                 
                 15212345678 ->
                {
                    code = 403;
                    message = "The phone is not found ";
                }
                 
                 13812345678->
                {
                    code = 403;
                    message = "The phone is registered before ";
                }
                 
                {
                    code = 200;
                    data = 13812345678;
                    message = ok;
                }
                 */
                
                let valueJson = JSON(value)
                gLog.verbose("valueJson=\(valueJson)")
                /*
                {
                  "message" : "ok",
                  "code" : 200,
                  "data" : "13812345678"
                }

                {
                  "message" : "ok",
                  "code" : 200,
                  "data" : {
                    "dealer" : "guanhai",
                    "id" : 10000101,
                    "name" : "Crifan Li",
                    "password" : "111111",
                    "phone" : "13812345678",
                    "jiugongge" : "1,2,3,4",
                    "role" : "sales_consultant",
                    "created" : 1464770891756
                  }
                }
                 */
                
                respJsonHandler(Alamofire.Result.Success(valueJson), mergedAllPara: mergedExtraPara)

            case .Failure(let error):
                var errorStr:String = error.localizedDescription

                if errorStr.isEmpty {
                    errorStr = error.localizedFailureReason ?? ""
                }
                
                gLog.error("\(httpMethod) \(url) error: \(errorStr), detail:\(error)")
                //GET http://qapp.chinacloudapp.cn/token/generate error: The data couldn’t be read because it isn’t in the correct format., detail:Error Domain=NSCocoaErrorDomain Code=3840 "Invalid value around character 0." UserInfo={NSDebugDescription=Invalid value around character 0.}

                //let error:NSError = NSError(domain: HttpErrorDomain, code: statusCode, userInfo: [
                let returnError:NSError = NSError(domain: error.domain, code: error.code, userInfo: [
                    "message"   : errorStr,
                    "code"      : statusCode,
                    "NSDebugDescription" : error.userInfo["NSDebugDescription"] ?? "",
                    ])
                respJsonHandler(Alamofire.Result.Failure(returnError), mergedAllPara: mergedExtraPara)
            }
        })
    })
}

func getUrlRespDataJson_async(httpMethod:Alamofire.Method, url:String, parameters: [String : AnyObject]? = nil, headers: [String : String]? = nil, extraPara:Dictionary<String, AnyObject>? = nil, respJsonHandler: (Alamofire.Result<JSON, NSError>, mergedAllPara:Dictionary<String, AnyObject>) -> Void) {
    gLog.info("httpMethod=\(httpMethod), url=\(url), parameters=\(parameters), headers=\(headers), extraPara=\(extraPara), respJsonHandler=\(respJsonHandler)")
    //httpMethod=GET, url=http://qapp.chinacloudapp.cn/open/phone/13812345678, parameters=nil, headers=nil, respJsonHandler=(Function)
    //httpMethod=GET, url=http://qapp.chinacloudapp.cn/app/user/10000010/customer/160602000001, parameters=nil, headers=nil, extraPara=Optional(["curCustomerItem": <SalesApp.CustomerItem: 0x78e9b9e0>,name=范奇峰老婆6,isStar=false]), respJsonHandler=(Function)

    dispatchBackground_async({
        var curHeader = headers ?? Dictionary<String, String>()
        
        if !gCurUserItem.accessToken.isEmpty {
            curHeader["authenticate"] = "token " + gCurUserItem.accessToken
            //headers=["authenticate": "token he9jjpvgtjcph8681qb5fbs0al"]
        }

        gLog.debug("headers=\(curHeader)")

        getUrlRespJson_async(httpMethod, url: url, parameters: parameters, headers: curHeader, extraPara: extraPara, respJsonHandler: { respResult, mergedAllPara in
            gLog.info("respResult=\(respResult)")

            switch respResult {
            case .Success(let respJson):
                gLog.info("respJson=\(respJson)")
                
                /*
                {
                  "message" : "ok",
                  "code" : 200,
                  "data" : {
                    "dealer" : "guanhai",
                    "id" : 10000101,
                    "name" : "Crifan Li",
                    "password" : "111111",
                    "phone" : "13812345678",
                    "jiugongge" : "1,2,3,4",
                    "role" : "sales_consultant",
                    "created" : 1464770891756
                  }
                }
                 */
                
                /*
                 15212345678 ->
                {
                    code = 403;
                    message = "The phone is not found ";
                }
                 
                 13812345678->
                {
                    code = 403;
                    message = "The phone is registered before ";
                }
                 
                {
                    code = 200;
                    data = 13812345678;
                    message = ok;
                }
                 */
                
                let statusCode = respJson["code"].int ?? 0
                gLog.debug("statusCode=\(statusCode)")

                if statusCode == 200 {
                    //if let dataDict = respJson["data"].dictionary {
                    let dataObj = respJson["data"].object
                    //maybe int/json/string/...
                    gLog.verbose("dataObj=\(dataObj)")
                    //dataObj=13812345678
                    //dataObj=10000010
                    
                    let dataJson:JSON = JSON(dataObj)
                    gLog.verbose("dataJson=\(dataJson)")
                    //dataJson=13812345678
                    //dataJson.string -> 13812345678

                    respJsonHandler(Alamofire.Result.Success(dataJson), mergedAllPara: mergedAllPara)
                } else {
                    let message = respJson["message"].string ?? ""
                    gLog.error("\(httpMethod) \(url) message=\(message)")
                    
                    /*
                    {
                      "message" : "手机号码已经注册|403105",
                      "code" : 403
                    }
                     
                    respJson={
                      "message" : "There was an error processing your request. It has been logged (ID f826f11a0495f196).",
                      "code" : 500
                    }
                     */
                    
                    //parse message to message + subCode
                    let messageStrArr = message.splitToStrArr("|")
                    
                    var messageStr:String = message
                    var subCode:Int = 0
                    
                    if messageStrArr.count > 1 {
                        messageStr = messageStrArr[0]
                        subCode = Int(messageStrArr[1]) ?? 0
                    }

                    let error:NSError = NSError(domain: HttpErrorDomain, code: statusCode, userInfo: [
                        "message"   : messageStr,
                        "code"      : statusCode,
                        "subCode"   : subCode,
                        ])

                    respJsonHandler(Alamofire.Result.Failure(error), mergedAllPara: mergedAllPara)
                }

            case .Failure(let error):
                gLog.error("\(httpMethod) \(url) error: \(error)")

                respJsonHandler(Alamofire.Result.Failure(error), mergedAllPara: mergedAllPara)
            }
        })
    })
}


func getHttpRespErrMsg(error:NSError) -> String {
    var errMsg = ""
    
    if let message = error.userInfo["message"] as? String {
        errMsg = message
    }
    
    return errMsg
}


func genFullErrorStr(defaultError:String, error:NSError, noColon:Bool = false) -> String {
    var fullErrorStr = defaultError
    
    let errorMessage = getHttpRespErrMsg(error)

    if !errorMessage.isEmpty {
        if noColon {
            fullErrorStr += errorMessage
        } else {
            fullErrorStr += ": " + errorMessage
        }
    }
    
    return fullErrorStr
}


//convert query dict to query string, suport input base url, and auto encode if special(ZhCN) chars
/*
     (1)
     urlBase=""
     queryParaDict=
     {
         "t" : 1510906527744,
         "tabId" : ""
     }
     -> "?t=1510906527744&tabId="
     (2)
     urlBase="http://xx.xx.xx.xx/skrDev/src/report/dealer.html"
     queryParaDict=
     {
         "t" : 1510906527744,
         "tabId" : ""
     }
     -> "http://xx.xx.xx.xx/skrDev/src/report/dealer.html?t=1510906527744&tabId="
     (3)
     urlBase="http://xx.xx.xx.xx/skrDev/src/report/dealer.html"
     queryParaDict=
     {
         "t" : 1510908755968,
         "tabId" : "第二个Tab"
     }
     -> "http://xx.xx.xx.xx/skrDev/src/report/dealer.html?t=1510908755968&tabId=%E7%AC%AC%E4%BA%8C%E4%B8%AATab"
 */
func queryDictToStr(urlBase:String = "", queryParaDict: [String: Any]) -> String {
    print("queryDictToStr: urlBase=\(urlBase), queryParaDict=\(queryParaDict)")
    
    var urlComponents = URLComponents()
    
    if !urlBase.isEmpty {
        if let baseUrl = URL(string: urlBase) {
            if let urlComponentsWithBase = URLComponents(url: baseUrl, resolvingAgainstBaseURL: false) {
                urlComponents = urlComponentsWithBase
//                Printing description of urlComponentsWithBase:
//                ▿ http://xx.xx.xx.xx/skrDev/src/report/dealer.html
//                - scheme : "http"
//                - host : "xx.xx.xx.xx"
//                - path : "/skrDev/src/report/dealer.html"
            }
        }
    }
//    print("url=\(urlBase) -> host=\(urlComponents.host), path=\(urlComponents.path), port=\(urlComponents.port)")
    
    urlComponents.queryItems = queryParaDict.map { (arg) -> URLQueryItem in
        let (key, value) = arg
        let valueStr = "\(value)"
        return URLQueryItem(name: key, value: valueStr)
    }
    
//    print("query=\(urlComponents.query), queryItems=\(urlComponents.queryItems)")
    
    var queryParaStr = ""
    if let componentsAbsUrl = urlComponents.url?.absoluteString {
        queryParaStr = componentsAbsUrl
        //"?t=1510906527744&tabId="
        //http://xx.xx.xx.xx/skrDev/src/report/dealer.html?t=1510908755968&tabId=%E7%AC%AC%E4%BA%8C%E4%B8%AATab
    }
    
    //Note: above urlComponents.url?.absoluteString have encode url, here should NOT encode again
    //        let encodedQueryParaStr = queryParaStr.encodedUrl
    let encodedQueryParaStr = queryParaStr
    
    return encodedQueryParaStr
}
