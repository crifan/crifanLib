//
//  CrifanLibHttpDemo.swift
//  SalesApp
//
//  Created by licrifan on 16/6/7.
//  Copyright © 2016年 licrifan. All rights reserved.
//
//  Last Update: 2016-06-07

import UIKit
import Alamofire
import SwiftyJSON

//unuseful function CrifanLibHttpDemo, just for demo usage for CrifanLibHttp
func CrifanLibHttpDemo(){
    
    //demo get
    func getUserId() {
        gLog.info("")
        
        //let curPhone:String = self.loginView.phoneTextField.text!
        let curPhone:String = "13800000000"
        gLog.debug("curPhone=\(curPhone)")
        
        getUrlRespDataJson_async(
            .GET,
            url: ServerApi.getUserIdUrl(curPhone),
            respJsonHandler: getUserIdHandler)
    }
    
    func getUserIdHandler(respDataJson:Alamofire.Result<JSON, NSError>) {
        gLog.verbose("respDataJson.debugDescription=\(respDataJson.debugDescription)")
        
        switch respDataJson {
        case .Success(let dataJson):
            gLog.verbose("dataJson=\(dataJson)")
            
            gCurUserItem.id = dataJson.int!
            
            gLog.info("成功获取用ID：\(gCurUserItem.id)")
            //成功获取用ID：10000010
            
            gCurUserItem.phone = "13800000000"
            
            gCurUserItem.password = "123456"
            
            //getAcessToken()
        case .Failure(let error):
            gLog.verbose("error=\(error)")
            
            let fullErrStr = genFullErrorStr("获取用户ID失败", error: error)
            gLog.verbose("fullErrStr=\(fullErrStr)")
            //self.noticeError(fullErrStr, autoClear: true)
        }
    }
    
    //demo Post with parameters
    
    func getSmsCodeHandler(respDataJson:Alamofire.Result<JSON, NSError>) {
        gLog.verbose("respDataJson.debugDescription=\(respDataJson.debugDescription)")
        //respDataJson.debugDescription=SUCCESS: 13812345678
        //respDataJson.debugDescription=FAILURE: Error Domain=HttpErrorDomain Code=403 "(null)" UserInfo={message=The phone is not found , code=403}
        
        switch respDataJson {
        case .Success(let dataJson):
            gLog.verbose("dataJson=\(dataJson)")
            //dataJson=13812345678
            
        //self.noticeSuccess("已成功发送短信验证码，请注意查收", autoClear: true)
        case .Failure(let error):
            gLog.verbose("error=\(error)")
            //error=Error Domain=HttpErrorDomain Code=403 "(null)" UserInfo={message=The phone is not found , code=403}
            
            let errMsg = getHttpRespErrMsg(error)
            gLog.verbose("errMsg=\(errMsg)")
            
            //self.noticeError(errMsg, autoClear: true)
        }
    }
    
    //if validate4SShopCode() && validatePhonenumber(self.registerView.phoneTextField.text!) {
        getUrlRespDataJson_async(
            .POST,
            url: ServerApi.getSmsCodeUrl(),
            parameters: [
                //"phone"     : self.registerView.phoneTextField.text!,
                "codetype"  : "register",
                //"dealer"    : self.registerView.shop4SCodeTextField.text!,
            ],
            respJsonHandler: getSmsCodeHandler)
    //}
    

}