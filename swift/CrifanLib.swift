//
//  CrifanLib.swift
//  Crifan
//
//  Created by licrifan on 15/11/6.
//  Copyright © 2015年 licrifan. All rights reserved.
//
//  Last Update: 2016-06-07

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
 * Device functions
 ***************************************************************************/

public enum DeviceModel: String {
    //case Simulator = "Simulator/sandbox",
    case Simulator = "Simulator",
    iPod1          = "iPod 1",
    iPod2          = "iPod 2",
    iPod3          = "iPod 3",
    iPod4          = "iPod 4",
    iPod5          = "iPod 5",
    iPod6          = "iPod 6",
    iPad1          = "iPad 1",
    iPad2          = "iPad 2",
    iPad3          = "iPad 3",
    iPad4          = "iPad 4",
    iPhone1G       = "iPhone 1G",
    iPhone3G       = "iPhone 3G",
    iPhone3GS      = "iPhone 3GS",
    iPhone4        = "iPhone 4",
    iPhone4S       = "iPhone 4S",
    iPhone5        = "iPhone 5",
    iPhone5S       = "iPhone 5S",
    iPhone5C       = "iPhone 5C",
    iPadMini1      = "iPad Mini 1",
    iPadMini2      = "iPad Mini 2",
    iPadMini3      = "iPad Mini 3",
    iPadMini4      = "iPad Mini 4",
    iPadAir1       = "iPad Air 1",
    iPadAir2       = "iPad Air 2",
    iPadPro        = "iPad Pro",
    iPhone6        = "iPhone 6",
    iPhone6plus    = "iPhone 6 Plus",
    iPhone6S       = "iPhone 6S",
    iPhone6Splus   = "iPhone 6S Plus",
    iPhoneSE       = "iPhone SE",
    AppleWatch     = "Apple Watch",
    AppleTV        = "Apple TV",
    Unknown        = "Unknown"
}

//public extension UIDevice {
extension UIDevice {
//    public var curDeviceType: DeviceModel {
    var curDeviceType: DeviceModel {
        var systemInfo = utsname()
        uname(&systemInfo)
        let modelCode = withUnsafeMutablePointer(&systemInfo.machine) {
            ptr in String.fromCString(UnsafePointer<CChar>(ptr))
        }
        print("modelCode=\(modelCode)")
        //modelCode=Optional("x86_64")
        //modelCode=Optional("iPhone7,2")
        var modelMap : [ String : DeviceModel ] = [
            "i386"      : .Simulator,
            "x86_64"    : .Simulator,

            "iPod1,1"   : .iPod1,
            "iPod2,1"   : .iPod2,
            "iPod3,1"   : .iPod3,
            "iPod4,1"   : .iPod4,
            "iPod5,1"   : .iPod5,
            "iPod7,1"   : .iPod6,

            "iPad1,1"   : .iPad1,
            "iPad2,1"   : .iPad2,
            "iPad2,2"   : .iPad2,
            "iPad2,3"   : .iPad2,
            "iPad2,4"   : .iPad2,
            "iPad3,1"   : .iPad3,
            "iPad3,2"   : .iPad3,
            "iPad3,3"   : .iPad3,
            "iPad3,4"   : .iPad4,
            "iPad3,5"   : .iPad4,
            "iPad3,6"   : .iPad4,
            "iPad4,1"   : .iPadAir1,
            "iPad4,2"   : .iPadAir1,
            "iPad4,3"   : .iPadAir1,
            "iPad5,3"   : .iPadAir2,
            "iPad5,4"   : .iPadAir2,
            "iPad6,3"   : .iPadPro,
            "iPad6,4"   : .iPadPro,
            "iPad6,7"   : .iPadPro,
            "iPad6,8"   : .iPadPro,
            "iPad2,5"   : .iPadMini1,
            "iPad2,6"   : .iPadMini1,
            "iPad2,7"   : .iPadMini1,
            "iPad4,4"   : .iPadMini2,
            "iPad4,5"   : .iPadMini2,
            "iPad4,6"   : .iPadMini2,
            "iPad4,7"   : .iPadMini3,
            "iPad4,8"   : .iPadMini3,
            "iPad4,9"   : .iPadMini3,
            "iPad5,1"   : .iPadMini4,
            "iPad5,2"   : .iPadMini4,
            
            "iPhone1,1" : .iPhone1G,
            "iPhone1,2" : .iPhone3G,
            "iPhone2,1" : .iPhone3GS,
            "iPhone3,1" : .iPhone4,
            "iPhone3,2" : .iPhone4,
            "iPhone3,3" : .iPhone4,
            "iPhone4,1" : .iPhone4S,
            "iPhone5,1" : .iPhone5,
            "iPhone5,2" : .iPhone5,
            "iPhone5,3" : .iPhone5C,
            "iPhone5,4" : .iPhone5C,
            "iPhone6,1" : .iPhone5S,
            "iPhone6,2" : .iPhone5S,
            "iPhone7,1" : .iPhone6plus,
            "iPhone7,2" : .iPhone6,
            "iPhone8,1" : .iPhone6S,
            "iPhone8,2" : .iPhone6Splus,
            "iPhone8,4" : .iPhoneSE,
            
            "Watch1,1"  : .AppleWatch,
            "Watch1,2"  : .AppleWatch,
            
            "AppleTV2,1" : .AppleTV,
            "AppleTV3,1" : .AppleTV,
            "AppleTV3,2" : .AppleTV,
            "AppleTV5,3" : .AppleTV,
        ]
        
        if let model = modelMap[String.fromCString(modelCode!)!] {
            print("model=\(model)")
            //model=Simulator
            //model=iPhone6
            return model
        }

        return DeviceModel.Unknown
    }
    
    public var isPhone:Bool {
        return self.curDeviceType.rawValue.containsString("iPhone")
    }
    
    public var isPad:Bool {
        return self.curDeviceType.rawValue.containsString("iPad")
    }

    public var isPod:Bool {
        return self.curDeviceType.rawValue.containsString("iPod")
    }
    
    public var isSimulator:Bool {
        return self.curDeviceType.rawValue.containsString("Simulator")
    }

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
 * Number Related functions
 ***************************************************************************/
 
 //get random int number within range: lower<=random<=upper
func getRandomInRange(lower:Int, upper:Int) -> Int {
    return lower + Int(arc4random_uniform(UInt32(upper - lower + 1)))
}

//get unique random int array number within range: lower<=random<=upper
func getUniqueRandomArrayInRange(lower:Int, upper:Int, arrCount:Int) -> [Int] {
    //print("lower=\(lower), upper=\(upper), arrCount=\(arrCount)")
    
    let singleRoundNum:Int = upper - lower + 1
    //print("singleRoundNum=\(singleRoundNum)")
    
    let invalidRandomNum = upper + 1
    //print("invalidRandomNum=\(invalidRandomNum)")
    //var uniqueRandomArr:[Int] = [Int](count: arrCount, repeatedValue: invalidRandomNum)
    var uniqueRandomArr:[Int] = [Int]()
    //print("uniqueRandomArr=\(uniqueRandomArr)")
    
    let remain = arrCount % singleRoundNum
    //print("remain=\(remain)")
    var maxRoundNum = arrCount / singleRoundNum
    if remain > 0 {
        maxRoundNum += 1
    }
    //print("maxRoundNum=\(maxRoundNum)")
    let maxRoundIdx = maxRoundNum - 1
    //print("maxRoundIdx=\(maxRoundIdx)")

    for roundIdx in 0...maxRoundIdx {
        //print("roundIdx=\(roundIdx)")
        
        var curRoundMaxNum:Int = 0
        if roundIdx < maxRoundIdx {
            curRoundMaxNum = singleRoundNum
        }
        else if roundIdx == maxRoundIdx {
            curRoundMaxNum = arrCount - roundIdx * singleRoundNum
        }
        //print("curRoundMaxNum=\(curRoundMaxNum)")
        
        let curRoundMaxIdx = curRoundMaxNum - 1
        //print("curRoundMaxIdx=\(curRoundMaxIdx)")
        
        var curRoundUniqueRandomArr:[Int] = [Int](count: curRoundMaxNum, repeatedValue: invalidRandomNum)
        //print("curRoundUniqueRandomArr=\(curRoundUniqueRandomArr)")
        
        for idxWithinRound in 0...curRoundMaxIdx {
            //print("idxWithinRound=\(idxWithinRound)")
            var curRandomNum:Int
            
            repeat {
                curRandomNum = getRandomInRange(lower, upper: upper)
                //print("curRandomNum=\(curRandomNum)")
            }while(curRoundUniqueRandomArr.contains(curRandomNum))
            
            curRoundUniqueRandomArr[idxWithinRound] = curRandomNum
            //print("[\(idxWithinRound)] curRoundUniqueRandomArr=\(curRoundUniqueRandomArr)")
        }
        
        uniqueRandomArr += curRoundUniqueRandomArr
        //uniqueRandomArr.appendContentsOf(curRoundUniqueRandomArr)
        //print("uniqueRandomArr=\(uniqueRandomArr)")
    }
    
    return uniqueRandomArr
}

/***************************************************************************
 * String/Char Related functions
 ***************************************************************************/

func genSizeStr(sizeInBytes:Int64, unitSize:Int64 = 0, sizeFormat:String = "") -> String {
    let sizeB:Int64 = 1
    let sizeKB:Int64 = 1024
    let sizeMB:Int64 = sizeKB * 1024
    let sizeGB:Int64 = sizeMB * 1024
    let sizeTB:Int64 = sizeGB * 1024
    let sizePB:Int64 = sizeTB * 1024
    
//    print("\(Int16.max)") //32767
//    print("\(Int32.max)") //2147483647
//    print("\(Int64.max)") //9223372036854775807
//    print("\(Int.max)")   //9223372036854775807
    
    var sizeStr = ""
    var curUnitSize = unitSize
    var curSizeFormat = sizeFormat
    var suffixStr = ""
    
    //print("curUnitSize=\(curUnitSize), curSizeFormat=\(curSizeFormat)")
    
    if sizeInBytes < sizeKB {
        if curUnitSize == 0 {
            curUnitSize = sizeB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.0f"
        }
        
        suffixStr = " B"
    } else if (sizeInBytes >= sizeKB) && (sizeInBytes < sizeMB) {
        if curUnitSize == 0 {
            curUnitSize = sizeKB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " KB"
    } else if (sizeInBytes >= sizeMB) && (sizeInBytes < sizeGB) {
        if curUnitSize == 0 {
            curUnitSize = sizeMB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " MB"
    } else if (sizeInBytes >= sizeGB) && (sizeInBytes < sizeTB) {
        if curUnitSize == 0 {
            curUnitSize = sizeGB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " GB"
    } else if (sizeInBytes >= sizeTB) && (sizeInBytes < sizePB)  {
        if curUnitSize == 0 {
            curUnitSize = sizeTB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " TB"
    } else if sizeInBytes >= sizePB {
        if curUnitSize == 0 {
            curUnitSize = sizePB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " PB"
    }
    
    print("curUnitSize=\(curUnitSize), curSizeFormat=\(curSizeFormat)")
    
    let sizeFloat:Float = Float(sizeInBytes) / Float(curUnitSize)
    //print("sizeFloat=\(sizeFloat)")
    
    let sizeFloatStr = String(format: curSizeFormat, sizeFloat)
    //print("sizeFloatStr=\(sizeFloatStr)")
    
    sizeStr = sizeFloatStr + suffixStr
    
    print("sizeInBytes=\(sizeInBytes) -> sizeStr=\(sizeStr)")

    return sizeStr
}

//get first char(string) from input a string
func getFirstChar(str:String) -> String {
    var firstChar:String = ""
    if !str.isEmpty{
        //firstChar = str[Range(start: str.startIndex, end: str.startIndex.advancedBy(1))]
        firstChar = str[str.startIndex ..< str.startIndex.advancedBy(1)]
    }
    return firstChar
}

//get last char(string) from input a string
func getLastChar(str:String) -> String {
    var lastChar:String = ""
    if !str.isEmpty {
//        lastChar = str[Range(start: str.endIndex.advancedBy(-1), end:str.endIndex )]
        lastChar = str[str.endIndex.advancedBy(-1) ..< str.endIndex]
    }
    return lastChar
}


//split string into character array
func splitSingleStrToCharArr(strToSplit:String) -> [Character] {
    //print("strToSplit=\(strToSplit)") //strToSplit=周杰伦
    
    let splitedCharArr:[Character] = Array(strToSplit.characters)
    //print("splitedCharArr=\(splitedCharArr)") //splitedCharArr=["周", "杰", "伦"]
    
    return splitedCharArr
}


//merge character array into string
func mergeCharArrToSingleStr(charArr:[Character]) -> String {
    //print("charArr=\(charArr)") //charArr=["一", "个", "字", "符", "串"]
    
    let mergedSingleStr:String = String(charArr) //"一个字符串"
    //print("mergedSingleStr=\(mergedSingleStr)")
    
    return mergedSingleStr
}

//merge string array into single string
func mergeStrArrToSingleStr(strArr:[String]) -> String {
    //print("strArr=\(strArr)")
    
    var singleStr:String = ""
    
    for eachStr in strArr {
        singleStr += eachStr
    }
    //print("singleStr\(singleStr)")
    
    return singleStr
}


//translate chinese string into pinyin with accents
func translateChineseStrToPinyinWithAccents(chineseStr:String) -> String {
    //print("chineseStr=\(chineseStr)") //chineseStr=王八
    
    var translatedPinyinWithAccents:String = ""
    
    let zhcnStrToTranslate:CFMutableStringRef = NSMutableString(string: chineseStr)
    //print("zhcnStrToTranslate=\(zhcnStrToTranslate)") //zhcnStrToTranslate=王八
    
    let translatedOk:Bool = CFStringTransform(zhcnStrToTranslate, nil, kCFStringTransformMandarinLatin, false)
    //print("translatedOk=\(translatedOk)") //translatedOk=true
    
    if translatedOk {
        translatedPinyinWithAccents = zhcnStrToTranslate as String
        //print("translatedPinyinWithAccents=\(translatedPinyinWithAccents)")
    }
    
    return translatedPinyinWithAccents
}

//remove accents from (Chinese PinYin) string
func removeAccentsFromStr(strWithAccents:String) -> String {
    //print("strWithAccents=\(strWithAccents)") //áng shān sù jì
    
    var removedAccentsStr:String = ""
    
    let strWithAccentsRef:CFMutableStringRef = NSMutableString(string: strWithAccents)
    
    //method 1: kCFStringTransformStripCombiningMarks
    let translatedOk = CFStringTransform(strWithAccentsRef, nil, kCFStringTransformStripCombiningMarks, false)
    //    //method 2: kCFStringTransformStripDiacritics
    //    let translatedOk = CFStringTransform(strWithAccentsRef, nil, kCFStringTransformStripDiacritics, false)
    //print("translatedOk=\(translatedOk)") //true
    
    if translatedOk {
        removedAccentsStr = strWithAccentsRef as String
        //print("removedAccentsStr=\(removedAccentsStr)") //ang shan su ji
    }
    
    return removedAccentsStr
}

//translate Chinese characters string to characterStr:pinyin(without accents) dictionary list
//Note: here use dict list intead of dict to makesure returned key:value sequence can guaranteed
func translateChineseStrToCharPinyinDict(chineseStr:String) -> [[String:String]] {
    //print("chineseStr=\(chineseStr)") //昂山素季
    
    let noneSeperatorStr:String = ""
    //let chinseSingleCharStrArr:[String] = splitSingleStrToStrArr(chineseStr, seperatorStr: noneSeperatorStr)
    let chinseSingleCharStrArr:[String] = chineseStr.splitToStrArr(noneSeperatorStr)
    //print("chinseSingleCharStrArr=\(chinseSingleCharStrArr)") //["昂", "山", "素", "季"]
    
    var translatedCharPinyinDictList:[[String:String]] = [[String:String]]()

    //测试用户4
    for (idx, eachChineseCharStr) in chinseSingleCharStrArr.enumerate() {
        let translatedPinyinStrWithAccents:String = translateChineseStrToPinyinWithAccents(eachChineseCharStr)
//        print("translatedPinyinStrWithAccents=\(translatedPinyinStrWithAccents)") //cè

        let pinyinStrWithoutAccents:String = removeAccentsFromStr(translatedPinyinStrWithAccents)
//        print("pinyinStrWithoutAccents=\(pinyinStrWithoutAccents)") //ce
        
        translatedCharPinyinDictList.append([chinseSingleCharStrArr[idx] : pinyinStrWithoutAccents])
    }

    print("translatedCharPinyinDictList=\(translatedCharPinyinDictList)")
    //[["昂": "ang"], ["山": "shan"], ["素": "su"], ["季": "ji"]]
    //translatedCharPinyinDictList=[["测": "ce"], ["试": "shi"], ["用": "yong"], ["户": "hu"], ["4": "4"]]

    return translatedCharPinyinDictList
}

/***************************************************************************
 * View functions
 ***************************************************************************/

extension UIApplication {
    class func topViewController(base: UIViewController? = UIApplication.sharedApplication().keyWindow?.rootViewController) -> UIViewController? {
        if let nav = base as? UINavigationController {
            return topViewController(nav.visibleViewController)
        }
        if let tab = base as? UITabBarController {
            if let selected = tab.selectedViewController {
                return topViewController(selected)
            }
        }
        if let presented = base?.presentedViewController {
            return topViewController(presented)
        }
        return base
    }
}

func isCurrentShowingVc(inputVc:UIViewController) -> Bool {
    var isCurrentShow = false

//    print("inputVc=\(inputVc)")
    //inputVc=<JianDao.MessageTableViewController: 0x7a900680>
    
    //check whether is current showing UI
    if let topVC = UIApplication.topViewController() {
//        print("topVC=\(topVC)")
        //topVC=<JianDao.ConversationViewController: 0x7a99f280>
        
        if topVC == inputVc {
            isCurrentShow = true
        }
    }
    
    return isCurrentShow
}


func getCallerViewController(curVC:UIViewController) -> UIViewController? {
    //        let parentViewController = self.parentViewController
    //        print("parentViewController=\(parentViewController)")
    //        let presentationController = self.presentationController
    //        print("presentationController=\(presentationController)")
    //        let presentedViewController = self.presentedViewController
    //        print("presentedViewController=\(presentedViewController)")
    //        let presentingViewController = self.presentingViewController
    //        print("presentingViewController=\(presentingViewController)")
    
    //        if let naviViewControllers = self.navigationController?.viewControllers{
    //            for (idx,eachVC) in naviViewControllers.enumerate() {
    //                print("[\(idx)] \(eachVC)")
    //            }
    //        }
    
    /*
     parentViewController=Optional(<UINavigationController: 0x7fce92844e00>)
     presentationController=Optional(<_UIFullscreenPresentationController: 0x7fce914bd830>)
     presentedViewController=nil
     presentingViewController=Optional(<JianDao.LoginViewController: 0x7fce914baac0>)
     
     [0] <JianDao.MainViewController: 0x7f80db037600>
     [1] <JianDao.MessageTableViewController: 0x7f80dc23b000>
     [2] <JianDao.ConversationManageViewController: 0x7f80dc230080>
     [3] <JianDao.SelectPersonViewController: 0x7f80dc0bc0c0>
     */
    
    //    print("curVC=\(curVC)")
    //<JianDao.SelectPersonViewController: 0x7facfd9906c0>
    
    var calerVc:UIViewController? = nil
    
    if let naviViewControllers = curVC.navigationController?.viewControllers{
        if let lastVc = naviViewControllers.last {
            calerVc = lastVc
            //Optional(<JianDao.ConversationManageViewController: 0x7facfd93a870>)
        }
    }
    
    return calerVc
}

func doShowViewController(curVc:UIViewController, vcToShow:UIViewController) {
    print("curVc=\(curVc), vcToShow=\(vcToShow)")
    //doShowViewController curVc=<JianDao.PersonInfoViewController: 0x7aeebe10>, vcToShow=<JianDao.MessageTableViewController: 0x79f80b80>
    
    if existedViewController(vcToShow) {
        //pop to that view controller
        //print("curVc.navigationController?.viewControllers=\(curVc.navigationController?.viewControllers)")
        curVc.navigationController?.popToViewController(vcToShow, animated: true)
        //            print("curVc.navigationController?.viewControllers=\(curVc.navigationController?.viewControllers)")
    } else {
        curVc.showViewController(vcToShow, sender: curVc)
    }
}

func existedViewController(vc:UIViewController) -> Bool {
    var existedVc = false
    if let naviController = vc.navigationController{
        for eachVc in naviController.viewControllers {
            if eachVc == vc {
                print("found vc=\(vc) in navi viewControllers")
                existedVc = true
                break
            }
        }
    }
    
    return existedVc
}

/***************************************************************************
 * GCD functions
 ***************************************************************************/

func delayDispatch(delayTimeInSec:Double, inThread:dispatch_queue_t, thingsTodo:()->()) {
    let dispatchDelayTime = dispatch_time(
        DISPATCH_TIME_NOW,
        Int64(delayTimeInSec * Double(NSEC_PER_SEC))
    )
    
    dispatch_after(dispatchDelayTime, inThread, thingsTodo)
}

func delayDispatchInMainThread(delayTimeInSec:Double, thingsTodo:()->()) {
    let mainQueue = dispatch_get_main_queue()
    delayDispatch(delayTimeInSec, inThread: mainQueue, thingsTodo: thingsTodo)
}

func dispatchMain_sync(delayTimeInSec:Double = 0.0, thingsTodo:()->()) {
    delayDispatchInMainThread(delayTimeInSec, thingsTodo: thingsTodo)
}

func delayDispatchInBackgroundThread(delayTimeInSec:Double, thingsTodo:()->()) {
    let backgroundQueue = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0)
//    let backgroundQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0)
    delayDispatch(delayTimeInSec, inThread: backgroundQueue, thingsTodo: thingsTodo)
}

func dispatchBackground_async(thingsTodo:()->()) {
    let backgroundQueue = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0)
    dispatch_async(backgroundQueue, thingsTodo)
}

func dispatchUserInitiated_async(thingsTodo:()->()) {
    let userInitiatedQueue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)
    dispatch_async(userInitiatedQueue, thingsTodo)
}

func dispatchMain_async(thingsTodo:()->()) {
    let mainQueue = dispatch_get_main_queue()
    dispatch_async(mainQueue, thingsTodo)
}

