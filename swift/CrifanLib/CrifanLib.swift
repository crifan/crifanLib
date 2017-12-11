//
//  CrifanLib.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit
//import Foundation

/***************************************************************************
 * NSUserDefaults functions
 ***************************************************************************/

func isFirstRunApp() -> Bool {
    var isFirstRun = false
    
    let keyHasLaunchedBefore = "hasLaunchedBefore"
    
    let hasLaunchedBefore = NSUserDefaults.standardUserDefaults().boolForKey(keyHasLaunchedBefore)
    if hasLaunchedBefore  {
        isFirstRun = false
    }
    else {
        isFirstRun = true
        NSUserDefaults.standardUserDefaults().setBool(true, forKey: keyHasLaunchedBefore)
    }
    
    return isFirstRun
}

let kLastTimeIsLogined = "lastTimeIsLogined"

//last time is logined
func lastIsLogined() -> Bool {
    return NSUserDefaults.standardUserDefaults().boolForKey(kLastTimeIsLogined)
}

//record current time logined
func saveLastLogined(hasLogined:Bool) {
    NSUserDefaults.standardUserDefaults().setBool(hasLogined, forKey: kLastTimeIsLogined)
}

/***************************************************************************
 * Calculation functions
 ***************************************************************************/

func generateBase64Str(inputStr:String) -> String {
    print("inputStr=\(inputStr)") //user-4e21fc48-179d-4db9-a61b-eb2e7e2e033a:111111
    let inputData:NSData = inputStr.dataUsingEncoding(NSUTF8StringEncoding)!
//    let inputData = inputStr.dataUsingEncoding(NSASCIIStringEncoding)
    print("inputData=\(inputData)")
    //Optional(<75736572 2d346532 31666334 382d3137 39642d34 6462392d 61363162 2d656232 65376532 65303333 613a3131 31313131>)
    let base64Str:String = inputData.base64EncodedStringWithOptions([])
    //let base64Str:String = (inputData?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0)))!
//    let base64Str:String = (inputData?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength))!
    print("base64Str=\(base64Str)")
    //dXNlci00ZTIxZmM0OC0xNzlkLTRkYjktYTYxYi1lYjJlN2UyZTAzM2E6MTExMTEx
    return base64Str
}

/***************************************************************************
 * Date Time Related functions
 ***************************************************************************/


class CalculateElapsedTime: NSObject {
    static var gCalcTime:[String:CalculateElapsedTime] = [String:CalculateElapsedTime]()
    static var gCalcTimeSummary:[String:Double] = [String:Double]()

    let uniqueId:String

    var startTime:NSDate
    var endTime:NSDate

    var elapsedTimeInSec:Double {
        let diffTimeInSec:Double = self.endTime.timeIntervalSinceDate(self.startTime)
        return diffTimeInSec
    }
    
    init(uniqueId:String = ""){
        self.uniqueId = uniqueId

        self.startTime = NSDate()
        self.endTime = self.startTime
    }

    func start() -> NSDate {
        self.reset()
        
        return self.startTime
    }
    
    func stop() -> Double {
        self.endTime = NSDate()
        
        return elapsedTimeInSec
    }

    func reset(){
        self.startTime = NSDate()
        self.endTime = self.startTime
    }
}

func calcTimeStart(uniqueId:String){
    print("\(uniqueId)")
    
    let calcTime = CalculateElapsedTime()
    CalculateElapsedTime.gCalcTime[uniqueId] = calcTime
}

func calcTimeEnd(uniqueId:String){
    if CalculateElapsedTime.gCalcTime.keys.contains(uniqueId) {
        let calcTime = CalculateElapsedTime.gCalcTime[uniqueId]!
        let elapsedTimeDouble = calcTime.stop()
        let elapsedTimeStr = String(format: "%.4f", elapsedTimeDouble)
        print("\(uniqueId) elapsedTime=\(elapsedTimeStr)")
        calcTime.reset()
        
        //save calculated time
        CalculateElapsedTime.gCalcTimeSummary[uniqueId] = elapsedTimeDouble
    }
}


/***************************************************************************
 * Phone functions
 ***************************************************************************/

func doPhoneCall(_ curPhone:String) -> Bool {
    var callOk = false
    
    if curPhone.notEmpty {
        let phoneTelStr = "tel://" + curPhone
        gLog.verbose("phoneTelStr=\(phoneTelStr)")
        //phoneTelStr=tel://13800001111
        if let phoneTelNsurl = URL(string: phoneTelStr) {
            gLog.verbose("phoneTelNsurl=\(phoneTelNsurl)")
            //phoneTelNsurl=tel://13800001111
            
            let application:UIApplication = UIApplication.shared
            if application.canOpenURL(phoneTelNsurl) {
                callOk = true
                
                UIApplication.shared.openURL(phoneTelNsurl)
            } else {
                //Note:
                //in iOS Simulator will fail:
                //canOpenURL: failed for URL: "tel://13800001111" - error: "This app is not allowed to query for scheme tel"
                print("application can not open: \(phoneTelNsurl)")
            }
        }
    } else {
        print("can not call for empty phone")
    }
    
    return callOk
}