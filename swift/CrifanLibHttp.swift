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



func getUrlRespJson_async(httpMethod:Alamofire.Method, url:String, parameters: [String : AnyObject]? = nil, headers: [String : String]? = nil, respJsonHandler: (Alamofire.Result<JSON, NSError>) -> Void) {
    gLog.info("httpMethod=\(httpMethod), url=\(url), parameters=\(parameters), headers=\(headers), respJsonHandler=\(respJsonHandler)")
    //httpMethod=POST, url=http://qapp.chinacloudapp.cn/open/code, parameters=Optional(["codetype": register, "phone": 13812345678]), headers=nil

    //merge input headers
    var currentHeaders:[String : String] = [
//        "Accept" : "application/json",
        "Content-Type" : "application/json",
    ]

    if let inputHeaders = headers {
        for eachKey in inputHeaders.keys {
            gLog.verbose("[\(eachKey)] = \(inputHeaders[eachKey]!)")
            currentHeaders[eachKey] = inputHeaders[eachKey]!
        }
    }
    
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
        gLog.verbose("request=\(response.request), response=\(response.response), statusCode=\(response.response?.statusCode), data=\(response.data), result=\(response.result)")
        /*
        request=Optional(<NSMutableURLRequest: 0x7964c340> { URL: http://qapp.chinacloudapp.cn/open/code }), response=Optional(<NSHTTPURLResponse: 0x78f82160> { URL: http://qapp.chinacloudapp.cn/open/code } { status code: 200, headers {
             Connection = "keep-alive";
             "Content-Length" = 48;
             "Content-Type" = "application/json;charset=UTF-8";
             Date = "Fri, 03 Jun 2016 08:42:18 GMT";
             Server = "nginx/1.10.1";
             } }), statusCode=Optional(200), data=Optional(<7b22636f 6465223a 3230302c 226d6573 73616765 223a226f 6b222c22 64617461 223a2231 35303531 34363436 3534227d>), result=SUCCESS
         */
        
        let statusCode = response.response?.statusCode ?? 0
        gLog.verbose("statusCode=\(statusCode)")

        switch response.result {
        case .Success(let value):
            gLog.verbose("value=\(value), value type=\(String(value.dynamicType)))")

            /*
            value={
                code = 200;
                data = 13812345678;
                message = ok;
            }, value type=__NSCFDictionary)
             
             15206188729 ->
            {
                code = 403;
                message = "The phone is not found ";
            }
             
             13862050544->
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
            
            respJsonHandler(Alamofire.Result.Success(valueJson))

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
            respJsonHandler(Alamofire.Result.Failure(returnError))
        }
    })
}

func getUrlRespDataJson_async(httpMethod:Alamofire.Method, url:String, parameters: [String : AnyObject]? = nil, headers: [String : String]? = nil, respJsonHandler: (Alamofire.Result<JSON, NSError>) -> Void) {
    gLog.info("httpMethod=\(httpMethod), url=\(url), parameters=\(parameters), headers=\(headers), respJsonHandler=\(respJsonHandler)")
    //httpMethod=GET, url=http://qapp.chinacloudapp.cn/open/phone/13812345678, parameters=nil, headers=nil, respJsonHandler=(Function)

    var curHeader = headers ?? Dictionary<String, String>()
    
    if !gCurUserItem.accessToken.isEmpty {
        curHeader["authenticate"] = "token " + gCurUserItem.accessToken
        gLog.debug("headers=\(curHeader)")
        //headers=["authenticate": "token he9jjpvgtjcph8681qb5fbs0al"]
    }
    
    getUrlRespJson_async(httpMethod, url: url, parameters: parameters, headers: curHeader, respJsonHandler: { respResult in
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
             15206188729 ->
            {
                code = 403;
                message = "The phone is not found ";
            }
             
             13862050544->
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

                respJsonHandler(Alamofire.Result.Success(dataJson))
                
//                    } else {
//                        let emptyDataJson = JSON("")
//                        respJsonHandler(Alamofire.Result.Success(emptyDataJson))
//                    }
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

                respJsonHandler(Alamofire.Result.Failure(error))
            }

        case .Failure(let error):
            gLog.error("\(httpMethod) \(url) error: \(error)")

            respJsonHandler(Alamofire.Result.Failure(error))
        }
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

