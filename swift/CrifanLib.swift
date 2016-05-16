//
//  CrifanLib.swift
//  Crifan
//
//  Created by licrifan on 15/11/6.
//  Copyright © 2015年 licrifan. All rights reserved.
//
//  Last Update: 2016-05-16

import UIKit
//import Foundation

//https://github.com/danielgindi/Charts
import Charts

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

extension NSDate
{
    //2015
    func Year() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentYear:Int = curCalendar.component(NSCalendarUnit.Year, fromDate: self)
        return componentYear
    }
    
    //11
    func Month() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentMonth:Int = curCalendar.component(NSCalendarUnit.Month, fromDate: self)
        return componentMonth
    }
    
    //28
    func Day() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentDay:Int = curCalendar.component(NSCalendarUnit.Day, fromDate: self)
        return componentDay
    }
    
    //10
    func Hour() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentHour:Int = curCalendar.component(NSCalendarUnit.Hour, fromDate: self)
        return componentHour
    }
    
    //39
    func Minute() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentMinute:Int = curCalendar.component(NSCalendarUnit.Minute, fromDate: self)
        return componentMinute
    }
    
    //18
    func Second() -> Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentSecond:Int = curCalendar.component(NSCalendarUnit.Second, fromDate: self)
        return componentSecond
    }
    
    //get short style date time string
    //11/28/15, 10:51 AM
    func toStringShort() -> String {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateStyle = NSDateFormatterStyle.ShortStyle
        dateFormatter.timeStyle = NSDateFormatterStyle.ShortStyle
        let shortStyleStr:String = dateFormatter.stringFromDate(self)
        return shortStyleStr
    }
    
    //get medium style date time string
    //Nov 28, 2015, 10:51:33 AM
    func toStringMedium() -> String {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateStyle = NSDateFormatterStyle.MediumStyle
        dateFormatter.timeStyle = NSDateFormatterStyle.MediumStyle
        let mediumStyleStr:String = dateFormatter.stringFromDate(self)
        return mediumStyleStr
    }
    
    //get long style date time string
    //November 28, 2015 at 10:51:33 AM GMT+8
    func toStringLong() -> String {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateStyle = NSDateFormatterStyle.LongStyle
        dateFormatter.timeStyle = NSDateFormatterStyle.LongStyle
        let longStyleStr:String = dateFormatter.stringFromDate(self)
        return longStyleStr
    }
    
    //get full style date time string
    //Saturday, November 28, 2015 at 10:51:33 AM China Standard Time
    func toStringFull() -> String {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateStyle = NSDateFormatterStyle.FullStyle
        dateFormatter.timeStyle = NSDateFormatterStyle.FullStyle
        let fullStyleStr:String = dateFormatter.stringFromDate(self)
        return fullStyleStr
    }
    
    //get date formatted string
    //2015/11/28 10:48:12
    func toString(dateFormat:String) -> String {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateFormat = dateFormat
        let formattedDatetimeStr:String = dateFormatter.stringFromDate(self)
        return formattedDatetimeStr
    }
    
    //parse input date time string into NSDate
    //input: 2015/11/28 12:01:02 and yyyy/MM/dd HH:mm:ss
    //output: Optional(2015-11-28 04:01:02 +0000)
    static func fromString(datetimeStr:String, dateFormat:String) -> NSDate? {
        let dateFormatter:NSDateFormatter = NSDateFormatter()
        dateFormatter.dateFormat = dateFormat
        let parsedDatetime:NSDate? = dateFormatter.dateFromString(datetimeStr)
        return parsedDatetime
    }
    
    //from milli second timestamp to NSDate
    static func fromTimestampMsec(timestampInt64InMsec:Int64) -> NSDate {
//        print("timestampInt64InMsec=\(timestampInt64InMsec)") //timestampInt64InMsec=1449805150184
        let timestampDoubleInSec:Double = Double(timestampInt64InMsec)/1000
//        print("timestampDoubleInSec=\(timestampDoubleInSec)") //timestampDoubleInSec=1449805150.184
        let parsedDate:NSDate = NSDate(timeIntervalSince1970: NSTimeInterval(timestampDoubleInSec))
//        print("parsedDate=\(parsedDate)") //parsedDate=2015-12-11 03:39:10 +0000
        
        return parsedDate
    }
    
    //static let emptyDate:NSDate = NSDate(timeIntervalSince1970: 0)
    var emptyDate:NSDate {
        return NSDate(timeIntervalSince1970: 0)
    }

}


public func ==(lhs: NSDate, rhs: NSDate) -> Bool {
    return lhs === rhs || lhs.compare(rhs) == .OrderedSame
}

public func <(lhs: NSDate, rhs: NSDate) -> Bool {
    return lhs.compare(rhs) == .OrderedAscending
}

extension NSDate: Comparable { }

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

extension String {
    var localized: String {
        //NSBundle.mainBundle()=NSBundle </Users/crifan/Library/Developer/CoreSimulator/Devices/63F89987-3382-42A5-BC13-AE102BEF98DB/data/Containers/Bundle/Application/41774451-6A9D-4562-8D0E-13302C32EF31/JianDao.app> (loaded)
        //return NSLocalizedString(self, tableName: nil, bundle: NSBundle.mainBundle(), value: "", comment: "")
//        return NSLocalizedString(self, tableName: "InfoPlist", bundle: NSBundle.mainBundle(), value: "", comment: self)
        //defaul table is Localizable -> Localizable.strings
        return NSLocalizedString(self, comment: self)
    }
}

// Very slightly adapted from http://stackoverflow.com/a/30141700/106244
// 99.99% Credit to Martin R!

// Mapping from XML/HTML character entity reference to character
// From http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
let HtmlCharacterEntitiesDict : [String: Character] = [

    // XML predefined entities:
    "&quot;"     : "\"",
    "&amp;"      : "&",
    "&apos;"     : "'",
    "&lt;"       : "<",
    "&gt;"       : ">",
    
    // HTML character entity references:
    "&nbsp;"     : "\u{00A0}",
    "&iexcl;"    : "\u{00A1}",
    "&cent;"     : "\u{00A2}",
    "&pound;"    : "\u{00A3}",
    "&curren;"   : "\u{00A4}",
    "&yen;"      : "\u{00A5}",
    "&brvbar;"   : "\u{00A6}",
    "&sect;"     : "\u{00A7}",
    "&uml;"      : "\u{00A8}",
    "&copy;"     : "\u{00A9}",
    "&ordf;"     : "\u{00AA}",
    "&laquo;"    : "\u{00AB}",
    "&not;"      : "\u{00AC}",
    "&shy;"      : "\u{00AD}",
    "&reg;"      : "\u{00AE}",
    "&macr;"     : "\u{00AF}",
    "&deg;"      : "\u{00B0}",
    "&plusmn;"   : "\u{00B1}",
    "&sup2;"     : "\u{00B2}",
    "&sup3;"     : "\u{00B3}",
    "&acute;"    : "\u{00B4}",
    "&micro;"    : "\u{00B5}",
    "&para;"     : "\u{00B6}",
    "&middot;"   : "\u{00B7}",
    "&cedil;"    : "\u{00B8}",
    "&sup1;"     : "\u{00B9}",
    "&ordm;"     : "\u{00BA}",
    "&raquo;"    : "\u{00BB}",
    "&frac14;"   : "\u{00BC}",
    "&frac12;"   : "\u{00BD}",
    "&frac34;"   : "\u{00BE}",
    "&iquest;"   : "\u{00BF}",
    "&Agrave;"   : "\u{00C0}",
    "&Aacute;"   : "\u{00C1}",
    "&Acirc;"    : "\u{00C2}",
    "&Atilde;"   : "\u{00C3}",
    "&Auml;"     : "\u{00C4}",
    "&Aring;"    : "\u{00C5}",
    "&AElig;"    : "\u{00C6}",
    "&Ccedil;"   : "\u{00C7}",
    "&Egrave;"   : "\u{00C8}",
    "&Eacute;"   : "\u{00C9}",
    "&Ecirc;"    : "\u{00CA}",
    "&Euml;"     : "\u{00CB}",
    "&Igrave;"   : "\u{00CC}",
    "&Iacute;"   : "\u{00CD}",
    "&Icirc;"    : "\u{00CE}",
    "&Iuml;"     : "\u{00CF}",
    "&ETH;"      : "\u{00D0}",
    "&Ntilde;"   : "\u{00D1}",
    "&Ograve;"   : "\u{00D2}",
    "&Oacute;"   : "\u{00D3}",
    "&Ocirc;"    : "\u{00D4}",
    "&Otilde;"   : "\u{00D5}",
    "&Ouml;"     : "\u{00D6}",
    "&times;"    : "\u{00D7}",
    "&Oslash;"   : "\u{00D8}",
    "&Ugrave;"   : "\u{00D9}",
    "&Uacute;"   : "\u{00DA}",
    "&Ucirc;"    : "\u{00DB}",
    "&Uuml;"     : "\u{00DC}",
    "&Yacute;"   : "\u{00DD}",
    "&THORN;"    : "\u{00DE}",
    "&szlig;"    : "\u{00DF}",
    "&agrave;"   : "\u{00E0}",
    "&aacute;"   : "\u{00E1}",
    "&acirc;"    : "\u{00E2}",
    "&atilde;"   : "\u{00E3}",
    "&auml;"     : "\u{00E4}",
    "&aring;"    : "\u{00E5}",
    "&aelig;"    : "\u{00E6}",
    "&ccedil;"   : "\u{00E7}",
    "&egrave;"   : "\u{00E8}",
    "&eacute;"   : "\u{00E9}",
    "&ecirc;"    : "\u{00EA}",
    "&euml;"     : "\u{00EB}",
    "&igrave;"   : "\u{00EC}",
    "&iacute;"   : "\u{00ED}",
    "&icirc;"    : "\u{00EE}",
    "&iuml;"     : "\u{00EF}",
    "&eth;"      : "\u{00F0}",
    "&ntilde;"   : "\u{00F1}",
    "&ograve;"   : "\u{00F2}",
    "&oacute;"   : "\u{00F3}",
    "&ocirc;"    : "\u{00F4}",
    "&otilde;"   : "\u{00F5}",
    "&ouml;"     : "\u{00F6}",
    "&divide;"   : "\u{00F7}",
    "&oslash;"   : "\u{00F8}",
    "&ugrave;"   : "\u{00F9}",
    "&uacute;"   : "\u{00FA}",
    "&ucirc;"    : "\u{00FB}",
    "&uuml;"     : "\u{00FC}",
    "&yacute;"   : "\u{00FD}",
    "&thorn;"    : "\u{00FE}",
    "&yuml;"     : "\u{00FF}",
    "&OElig;"    : "\u{0152}",
    "&oelig;"    : "\u{0153}",
    "&Scaron;"   : "\u{0160}",
    "&scaron;"   : "\u{0161}",
    "&Yuml;"     : "\u{0178}",
    "&fnof;"     : "\u{0192}",
    "&circ;"     : "\u{02C6}",
    "&tilde;"    : "\u{02DC}",
    "&Alpha;"    : "\u{0391}",
    "&Beta;"     : "\u{0392}",
    "&Gamma;"    : "\u{0393}",
    "&Delta;"    : "\u{0394}",
    "&Epsilon;"  : "\u{0395}",
    "&Zeta;"     : "\u{0396}",
    "&Eta;"      : "\u{0397}",
    "&Theta;"    : "\u{0398}",
    "&Iota;"     : "\u{0399}",
    "&Kappa;"    : "\u{039A}",
    "&Lambda;"   : "\u{039B}",
    "&Mu;"       : "\u{039C}",
    "&Nu;"       : "\u{039D}",
    "&Xi;"       : "\u{039E}",
    "&Omicron;"  : "\u{039F}",
    "&Pi;"       : "\u{03A0}",
    "&Rho;"      : "\u{03A1}",
    "&Sigma;"    : "\u{03A3}",
    "&Tau;"      : "\u{03A4}",
    "&Upsilon;"  : "\u{03A5}",
    "&Phi;"      : "\u{03A6}",
    "&Chi;"      : "\u{03A7}",
    "&Psi;"      : "\u{03A8}",
    "&Omega;"    : "\u{03A9}",
    "&alpha;"    : "\u{03B1}",
    "&beta;"     : "\u{03B2}",
    "&gamma;"    : "\u{03B3}",
    "&delta;"    : "\u{03B4}",
    "&epsilon;"  : "\u{03B5}",
    "&zeta;"     : "\u{03B6}",
    "&eta;"      : "\u{03B7}",
    "&theta;"    : "\u{03B8}",
    "&iota;"     : "\u{03B9}",
    "&kappa;"    : "\u{03BA}",
    "&lambda;"   : "\u{03BB}",
    "&mu;"       : "\u{03BC}",
    "&nu;"       : "\u{03BD}",
    "&xi;"       : "\u{03BE}",
    "&omicron;"  : "\u{03BF}",
    "&pi;"       : "\u{03C0}",
    "&rho;"      : "\u{03C1}",
    "&sigmaf;"   : "\u{03C2}",
    "&sigma;"    : "\u{03C3}",
    "&tau;"      : "\u{03C4}",
    "&upsilon;"  : "\u{03C5}",
    "&phi;"      : "\u{03C6}",
    "&chi;"      : "\u{03C7}",
    "&psi;"      : "\u{03C8}",
    "&omega;"    : "\u{03C9}",
    "&thetasym;" : "\u{03D1}",
    "&upsih;"    : "\u{03D2}",
    "&piv;"      : "\u{03D6}",
    "&ensp;"     : "\u{2002}",
    "&emsp;"     : "\u{2003}",
    "&thinsp;"   : "\u{2009}",
    "&zwnj;"     : "\u{200C}",
    "&zwj;"      : "\u{200D}",
    "&lrm;"      : "\u{200E}",
    "&rlm;"      : "\u{200F}",
    "&ndash;"    : "\u{2013}",
    "&mdash;"    : "\u{2014}",
    "&lsquo;"    : "\u{2018}",
    "&rsquo;"    : "\u{2019}",
    "&sbquo;"    : "\u{201A}",
    "&ldquo;"    : "\u{201C}",
    "&rdquo;"    : "\u{201D}",
    "&bdquo;"    : "\u{201E}",
    "&dagger;"   : "\u{2020}",
    "&Dagger;"   : "\u{2021}",
    "&bull;"     : "\u{2022}",
    "&hellip;"   : "\u{2026}",
    "&permil;"   : "\u{2030}",
    "&prime;"    : "\u{2032}",
    "&Prime;"    : "\u{2033}",
    "&lsaquo;"   : "\u{2039}",
    "&rsaquo;"   : "\u{203A}",
    "&oline;"    : "\u{203E}",
    "&frasl;"    : "\u{2044}",
    "&euro;"     : "\u{20AC}",
    "&image;"    : "\u{2111}",
    "&weierp;"   : "\u{2118}",
    "&real;"     : "\u{211C}",
    "&trade;"    : "\u{2122}",
    "&alefsym;"  : "\u{2135}",
    "&larr;"     : "\u{2190}",
    "&uarr;"     : "\u{2191}",
    "&rarr;"     : "\u{2192}",
    "&darr;"     : "\u{2193}",
    "&harr;"     : "\u{2194}",
    "&crarr;"    : "\u{21B5}",
    "&lArr;"     : "\u{21D0}",
    "&uArr;"     : "\u{21D1}",
    "&rArr;"     : "\u{21D2}",
    "&dArr;"     : "\u{21D3}",
    "&hArr;"     : "\u{21D4}",
    "&forall;"   : "\u{2200}",
    "&part;"     : "\u{2202}",
    "&exist;"    : "\u{2203}",
    "&empty;"    : "\u{2205}",
    "&nabla;"    : "\u{2207}",
    "&isin;"     : "\u{2208}",
    "&notin;"    : "\u{2209}",
    "&ni;"       : "\u{220B}",
    "&prod;"     : "\u{220F}",
    "&sum;"      : "\u{2211}",
    "&minus;"    : "\u{2212}",
    "&lowast;"   : "\u{2217}",
    "&radic;"    : "\u{221A}",
    "&prop;"     : "\u{221D}",
    "&infin;"    : "\u{221E}",
    "&ang;"      : "\u{2220}",
    "&and;"      : "\u{2227}",
    "&or;"       : "\u{2228}",
    "&cap;"      : "\u{2229}",
    "&cup;"      : "\u{222A}",
    "&int;"      : "\u{222B}",
    "&there4;"   : "\u{2234}",
    "&sim;"      : "\u{223C}",
    "&cong;"     : "\u{2245}",
    "&asymp;"    : "\u{2248}",
    "&ne;"       : "\u{2260}",
    "&equiv;"    : "\u{2261}",
    "&le;"       : "\u{2264}",
    "&ge;"       : "\u{2265}",
    "&sub;"      : "\u{2282}",
    "&sup;"      : "\u{2283}",
    "&nsub;"     : "\u{2284}",
    "&sube;"     : "\u{2286}",
    "&supe;"     : "\u{2287}",
    "&oplus;"    : "\u{2295}",
    "&otimes;"   : "\u{2297}",
    "&perp;"     : "\u{22A5}",
    "&sdot;"     : "\u{22C5}",
    "&lceil;"    : "\u{2308}",
    "&rceil;"    : "\u{2309}",
    "&lfloor;"   : "\u{230A}",
    "&rfloor;"   : "\u{230B}",
    "&lang;"     : "\u{2329}",
    "&rang;"     : "\u{232A}",
    "&loz;"      : "\u{25CA}",
    "&spades;"   : "\u{2660}",
    "&clubs;"    : "\u{2663}",
    "&hearts;"   : "\u{2665}",
    "&diams;"    : "\u{2666}",
    
]

extension String {
    func replace(from:String, to:String) -> String {
      return self.stringByReplacingOccurrencesOfString(from, withString: to)
    }
    
    var containsChineseCharacters: Bool {
        return self.rangeOfString("\\p{Han}", options: .RegularExpressionSearch) != nil
    }
    
    var isAllChineseCharacters: Bool {
        var isAll = false
        
        if let chineseRangeIdx = self.rangeOfString("\\p{Han}+", options: .RegularExpressionSearch) {
            print("chineseRangeIdx=\(chineseRangeIdx)")
            let chineseSubStr = self.substringWithRange(chineseRangeIdx)
            print("chineseSubStr=\(chineseSubStr)")
            if chineseSubStr == self {
                isAll = true
            }
        }
        return  isAll
    }
    
    var isAllLetters: Bool {
        var isAll = true
        
        for eachChar in self.characters {
            if !( ((eachChar >= "A") && (eachChar <= "Z")) || ((eachChar >= "a") && (eachChar <= "z")) ){
                isAll = false
                break
            }
        }
        
        return isAll
    }
    
    var isAllDigits: Bool {
        var isAll = true
        
        for eachChar in self.characters {
            if !((eachChar >= "0") && (eachChar <= "9")){
                isAll = false
                break
            }
        }
        
        return isAll
    }
    
    //Trims white space and new line characters, returns a new string
    func trim() -> String {
        return stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceAndNewlineCharacterSet())
    }

    
    //method 1: use NSAttributedString and NSHTMLTextDocumentType to filter out html entity
    //pros: can filter out all html tags ?
    //cons:
    //1. must run in main thread otherwise crash
    //2. will remove html tags ?
//    var decodedHtml:String {
//        var decodedHtmlStr = self
//        
//        //print("decodedHtmlStr=\(decodedHtmlStr)")
//        do {
//            if let encodedData = decodedHtmlStr.dataUsingEncoding(NSUTF8StringEncoding) {
//                let attributedOptions : [String: AnyObject] = [
//                    NSDocumentTypeDocumentAttribute         : NSHTMLTextDocumentType,
//                    NSCharacterEncodingDocumentAttribute    : NSUTF8StringEncoding
//                ]
//                //print("attributedOptions=\(attributedOptions)") //["DocumentType": NSHTML, "CharacterEncoding": 4]
//                let attributedString = try NSAttributedString(data: encodedData, options: attributedOptions, documentAttributes: nil)
//                //print("attributedString=\(attributedString)")
//                /*
//                attributedString=@Anglia‍ again测试{
//                    NSColor = "UIDeviceRGBColorSpace 0 0 0 1";
//                    NSFont = "<UICTFont: 0x7e01b0a0> font-family: \"Times New Roman\"; font-weight: normal; font-style: normal; font-size: 12.00pt";
//                    NSKern = 0;
//                    NSParagraphStyle = "Alignment 4, LineSpacing 0, ParagraphSpacing 0, ParagraphSpacingBefore 0, HeadIndent 0, TailIndent 0, FirstLineHeadIndent 0, LineHeight 15/0, LineHeightMultiple 0, LineBreakMode 0, Tabs (\n), DefaultTabInterval 36, Blocks (\n), Lists (\n), BaseWritingDirection 0, HyphenationFactor 0, TighteningForTruncation NO, HeaderLevel 0";
//                    NSStrokeColor = "UIDeviceRGBColorSpace 0 0 0 1";
//                    NSStrokeWidth = 0;
//                }
//                */
//                decodedHtmlStr = attributedString.string
//                print("decodedHtmlStr=\(decodedHtmlStr)")
//            }
//        } catch {
//            print("decodedHtml error: \(error)")
//        }
//        
//        return decodedHtmlStr
//    }
    
    
    //method 2: use char entity decode
    //pros: only decode html entity -> not filter out html tags
    //cons:
    
    
    /// Returns a new string made by removing in the `String`
    /// anything enclosed in HTML brackets <>
    public var strippedHtmlTags: String {
        return stringByReplacingOccurrencesOfString("<[^>]+>", withString: "", options: .RegularExpressionSearch, range: nil);
    }

    /// Returns a new string made by replacing in the `String`
    /// all HTML character entity references with the corresponding
    /// character.
    public var decodedHtmlEntities: String {
        return decodeHTMLEntities().decodedString
    }
    
    /// Returns a tuple containing the string made by relpacing in the
    /// `String` all HTML character entity references with the corresponding
    /// character. Also returned is an array of offset information describing
    /// the location and length offsets for each replacement. This allows
    /// for the correct adjust any attributes that may be associated with
    /// with substrings within the `String`
    func decodeHTMLEntities() -> (decodedString: String, replacementOffsets: [(index: String.Index, offset: String.Index.Distance)]) {
        
        // ===== Utility functions =====
        
        // Record the index offsets of each replacement
        // This allows anyone to correctly adjust any attributes that may be
        // associated with substrings within the string
        var replacementOffsets: [(index: String.Index, offset: String.Index.Distance)] = []
        
        // Convert the number in the string to the corresponding
        // Unicode character, e.g.
        //    decodeNumeric("64", 10)   --> "@"
        //    decodeNumeric("20ac", 16) --> "€"
        func decodeNumeric(string : String, base : Int32) -> Character? {
            let code = UInt32(strtoul(string, nil, base))
            return Character(UnicodeScalar(code))
        }
        
        // Decode the HTML character entity to the corresponding
        // Unicode character, return `nil` for invalid input.
        //     decode("&#64;")    --> "@"
        //     decode("&#x20ac;") --> "€"
        //     decode("&lt;")     --> "<"
        //     decode("&foo;")    --> nil
        func decode(entity : String) -> Character? {
            if entity.hasPrefix("&#x") || entity.hasPrefix("&#X"){
                return decodeNumeric(entity.substringFromIndex(entity.startIndex.advancedBy(3)), base: 16)
            } else if entity.hasPrefix("&#") {
                return decodeNumeric(entity.substringFromIndex(entity.startIndex.advancedBy(2)), base: 10)
            } else {
                return HtmlCharacterEntitiesDict[entity]
            }
        }
        
        // ===== Method starts here =====
        
        var result = ""
        var position = startIndex
        
        // Find the next '&' and copy the characters preceding it to `result`:
        while let ampRange = self.rangeOfString("&", range: position ..< endIndex) {
            //result.extend(self[position ..< ampRange.startIndex])
            result.appendContentsOf(self[position ..< ampRange.startIndex])

            position = ampRange.startIndex
            
            // Find the next ';' and copy everything from '&' to ';' into `entity`
            if let semiRange = self.rangeOfString(";", range: position ..< endIndex) {
                let entity = self[position ..< semiRange.endIndex]
                if let decoded = decode(entity) {
                    
                    // Replace by decoded character:
                    result.append(decoded)

                    // Record offset
                    //let offset = (index: semiRange.endIndex, offset: 1 - distance(position, semiRange.endIndex))
                    let offset = (index: semiRange.endIndex, offset: 1 - position.distanceTo(semiRange.endIndex))
                    replacementOffsets.append(offset)
                    
                } else {
                    
                    // Invalid entity, copy verbatim:
                    //result.extend(entity)
                    result.appendContentsOf(entity)
                }
                position = semiRange.endIndex
            } else {
                // No matching ';'.
                break
            }
        }
        
        // Copy remaining characters to `result`:
        //result.extend(self[position ..< endIndex])
        result.appendContentsOf(self[position ..< endIndex])

        // Return results
        return (decodedString: result, replacementOffsets: replacementOffsets)
    }
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


//split string into string array, normally seperator is white space
//if origin string not containing white space, then pass the empty string here, will split to every single char as string
func splitSingleStrToStrArr(strToSplit:String, seperatorStr:String) -> [String] {
    //print("strToSplit=\(strToSplit), seperatorStr=\(seperatorStr)")
    
    var splitedStrArr:[String] = [String]()
    if !seperatorStr.isEmpty {
        let seperatorChar:Character = splitSingleStrToCharArr(seperatorStr)[0]
        splitedStrArr = strToSplit.characters.split(seperatorChar).map(String.init)
    }
    else
    {
        //split string(without space) into every single char as string
        let splitedCharArr:[Character] = splitSingleStrToCharArr(strToSplit)
        for eachChar in splitedCharArr {
            splitedStrArr.append(String(eachChar))
        }
    }
    
    //print("splitedStrArr=\(splitedStrArr)")
    
    return splitedStrArr
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
    let chinseSingleCharStrArr:[String] = splitSingleStrToStrArr(chineseStr, seperatorStr: noneSeperatorStr)
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
 * UITextView/UILabel Related functions
 ***************************************************************************/

//calc real text size for UITextView text
func calcTexViewTextSize(text:String, font:UIFont, widthLimit:CGFloat)
    -> CGSize {
    let tmpTextView = UITextView(frame: CGRectZero)
    tmpTextView.font = font
    tmpTextView.text = text
    //Terminating app due to uncaught exception 'NSInternalInconsistencyException', reason: 'Only run on the main thread!'
    let realTextSize = tmpTextView.sizeThatFits(CGSize(width: widthLimit, height: CGFloat.max))
    //print("calculated realTextSize=\(realTextSize)")
    
    return realTextSize
}

//caculate text size for UILabel text
func calcLabelTextSize(text:String, font:UIFont) -> CGSize {
    let textLabel:UILabel = UILabel()
    textLabel.text = text
    textLabel.font = font
    textLabel.sizeToFit()
    let labelTextSize:CGSize = textLabel.bounds.size

    return labelTextSize
}

//caculate text size for UILabel text
func calcLabelTextSizeWithWidthLimit(text:String, font:UIFont, widthLimit:CGFloat) -> CGSize {
    let textLabel:UILabel = UILabel(frame: CGRectMake(
        0,
        0,
        widthLimit,
        CGFloat.max))
    textLabel.text = text
    textLabel.font = font
    textLabel.numberOfLines = 0
    //print("textLabel.frame=\(textLabel.frame)")
    textLabel.sizeToFit()
    //print("textLabel.frame=\(textLabel.frame)")
    
    let labelTextSize:CGSize = textLabel.bounds.size
    
    return labelTextSize
}


/***************************************************************************
 * Drawing Rectangle/Circle/Image Related functions
 ***************************************************************************/

func calculateScaledSize(curSize:CGSize, maxSize:CGSize) -> CGSize {
    var newWidth:CGFloat = curSize.width
    var newHeight:CGFloat = curSize.height
    
    let maxWidth:CGFloat = maxSize.width
    let maxHeight:CGFloat = maxSize.height
    
    let curWidth:CGFloat = curSize.width
    let curHeight:CGFloat = curSize.height
    
    let widthRatio:CGFloat = curWidth / maxWidth
    let heightRatio:CGFloat = curHeight / maxHeight
    
    if (curWidth >= maxWidth) && (curHeight >= maxHeight) {
        if widthRatio > heightRatio {
            newWidth = curWidth / widthRatio
            newHeight = curHeight / widthRatio
        } else {
            newWidth = curWidth / heightRatio
            newHeight = curHeight / heightRatio
        }
    } else if (curWidth < maxWidth) && (curHeight >= maxHeight) {
        newWidth = curWidth / heightRatio
        newHeight = curHeight / heightRatio
    } else if (curWidth >= maxWidth) && (curHeight < maxHeight) {
        newWidth = curWidth / widthRatio
        newHeight = curHeight / widthRatio
    } else {
        newWidth = curWidth
        newHeight = curHeight
    }
    
//    print("maxImgWidth=\(maxWidth), maxImgHeight=\(maxHeight)")
//    print("curImgWidth=\(curWidth), curImgHeight=\(curHeight)")
//    print("widthRatio=\(widthRatio), heightRatio=\(heightRatio)")
//    print("newWidth=\(newWidth), newHeight=\(newHeight)")
    
    let newSize = CGSizeMake(newWidth, newHeight)
    
    print("curSize=\(curSize), maxSize=\(maxSize) scale to newSize=\(newSize)")
    
    return newSize
}

//draw a circle fill with color
func drawCircleLayer(circleRadius:CGFloat, fillColor:UIColor) -> CAShapeLayer {
    let circlePath = UIBezierPath(
        arcCenter: CGPoint(x: circleRadius,y: circleRadius),
        radius: circleRadius,
        startAngle: CGFloat(0),
        endAngle:CGFloat(M_PI * 2),
        clockwise: true)
    
    let circleLayer = CAShapeLayer()
    circleLayer.path = circlePath.CGPath
    
    //circle inside fill color
    circleLayer.fillColor = fillColor.CGColor
    //        //set circle line color
    //        circleLayer.strokeColor = UIColor.yellowColor().CGColor
    //        //set circle line width
    //        circleLayer.lineWidth = 3.0
    
    return circleLayer
}

//draw a circle view
func drawCircle(circleRadius:CGFloat, fillColor:UIColor) -> UIView {
//    let circleRadius:CGFloat = 4
    let circleFrame = CGRectMake(0, 0, circleRadius * 2, circleRadius * 2)
    
    let circleView = UIView(frame: circleFrame)
    let circleLayer = drawCircleLayer(circleRadius, fillColor: fillColor)
    circleView.layer.addSublayer(circleLayer)
    return circleView
}

//draw a badge view
func drawBadgeView(badgeString:String, circleFillColor:UIColor) -> UIView {
    //let badgeRadius:CGFloat = 9
    let badgeRadius:CGFloat = 8.5
    let badgeFrame = CGRectMake(0, 0, badgeRadius * 2, badgeRadius * 2)
    
    let circleLayer = drawCircleLayer(badgeRadius, fillColor: circleFillColor)
    //let badgeView = UIView(frame: CGRectMake(0, 0, badgeRadius*2, badgeRadius*2))
    let badgeView = UIView(frame: badgeFrame)
    badgeView.layer.addSublayer(circleLayer)
    
    //let badgeLabel:UILabel = UILabel(frame: CGRectMake(0, 0, badgeRadius*2, badgeRadius*2))
    let badgeLabel:UILabel = UILabel(frame: badgeFrame)
    badgeLabel.text = badgeString
    badgeLabel.backgroundColor = UIColor.clearColor()
    badgeLabel.textAlignment = NSTextAlignment.Center
    badgeLabel.font = UIFont.systemFontOfSize(11)
    badgeLabel.textColor = UIColor.whiteColor()
    
    badgeView.addSubview(badgeLabel)
    badgeView.bringSubviewToFront(badgeLabel)
    
    return badgeView
}

//given an image, clip the round corner, return a round corner image
func drawCornerImage(image:UIImage, cornerRadius:CGFloat) -> UIImage {
    let clippedCornerImage:UIImage

    let tmpImageView = UIImageView(image: image)
    let opaque:Bool = false
    //let opaque:Bool = true
    //let scale:CGFloat = 1.0 //will cause round corner not clear == blur
    let scale:CGFloat = 0.0
    
    // Begin a new image that will be the new image with the rounded corners
    // here with the size of an UIImageView
    UIGraphicsBeginImageContextWithOptions(tmpImageView.bounds.size, opaque, scale);
    
    // Add a clip before drawing anything, in the shape of an rounded rect
    let cornerBezierPath = UIBezierPath(roundedRect: tmpImageView.bounds,
            cornerRadius: cornerRadius)
    cornerBezierPath.addClip()
    
    // Draw your image
    image.drawInRect(tmpImageView.bounds)
    
    // Get the clipped image
    clippedCornerImage = UIGraphicsGetImageFromCurrentImageContext();
    
    // Lets forget about that we were drawing
    UIGraphicsEndImageContext();
    
    return clippedCornerImage
}

//draw a rectangle image, filled with color, with size
func drawRectangleImage(size:CGSize, color:UIColor) -> UIImage {
//    //let opaque:Bool = false
//    let opaque:Bool = true
//    //let scale:CGFloat = 0
//    let scale:CGFloat = 1.0
//    UIGraphicsBeginImageContextWithOptions(size, opaque, scale)
    //same with UIGraphicsBeginImageContextWithOptions opaque=true, scale=1.0
    //-> omit alpha for bitmap
    //-> optimize drawing perfomance and reduce storage consume
    UIGraphicsBeginImageContext(size)
    
    let context = UIGraphicsGetCurrentContext()
    //CGContextSetLineWidth(context, 4.0)
    //CGContextSetStrokeColorWithColor(context, UIColor.blueColor().CGColor)
    let rectangle = CGRectMake(0, 0, size.width, size.height)
    CGContextAddRect(context, rectangle)
    CGContextSetFillColorWithColor(context, color.CGColor)
    CGContextFillRect(context, rectangle)
    
    // Drawing complete, retrieve the finished image and cleanup
    let image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return image
}

//draw a rectangle image, filled with color, with size, with label
func drawRectangleImageWithLabel(size:CGSize, color:UIColor, label:UILabel) -> UIImage {
    let opaque:Bool = false
    let scale:CGFloat = 0
    UIGraphicsBeginImageContextWithOptions(size, opaque, scale)
    
    let context = UIGraphicsGetCurrentContext()
    //CGContextSetLineWidth(context, 4.0)
    //CGContextSetStrokeColorWithColor(context, UIColor.blueColor().CGColor)
    let rectangle = CGRectMake(0, 0, size.width, size.height)
    CGContextAddRect(context, rectangle)
    CGContextSetFillColorWithColor(context, color.CGColor)
    CGContextFillRect(context, rectangle)
    
    //label.drawTextInRect(rectangle)
    label.layer.renderInContext(context!)
    
    // Drawing complete, retrieve the finished image and cleanup
    let image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return image
}

//merge multiple image to single image
func mergeMultipleToSingleImage(mergedFrameSize: CGSize, imageArr:[UIImage], drawPointArr: [CGPoint]) -> UIImage {
    var mergedImage:UIImage = UIImage()
    let opaque:Bool = false
    let scale:CGFloat = 0

    UIGraphicsBeginImageContextWithOptions(mergedFrameSize, opaque, scale)
    
    for index in 0...(imageArr.count - 1) {
        let curDrawPoint = drawPointArr[index]
        let curImage = imageArr[index]
        //print("[\(index)] curDrawPoint=\(curDrawPoint), curImage=\(curImage)")
        curImage.drawAtPoint(curDrawPoint, blendMode: CGBlendMode.Normal, alpha: 1.0)
    }
    
    mergedImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return mergedImage
}

extension UIImage {
//    func resize(scale:CGFloat)-> UIImage {
//        let imageView = UIImageView(frame: CGRect(origin: CGPoint(x: 0, y: 0), size: CGSize(width: size.width*scale, height: size.height*scale)))
//        imageView.contentMode = UIViewContentMode.ScaleAspectFit
//        imageView.image = self
//        UIGraphicsBeginImageContext(imageView.bounds.size)
//        imageView.layer.renderInContext(UIGraphicsGetCurrentContext()!)
//        let result = UIGraphicsGetImageFromCurrentImageContext()
//        UIGraphicsEndImageContext()
//        return result
//    }

//    func resizeToWidth(width:CGFloat)-> UIImage {
//        let imageView = UIImageView(frame: CGRect(origin: CGPoint(x: 0, y: 0), size: CGSize(width: width, height: CGFloat(ceil(width/size.width * size.height)))))
//        imageView.contentMode = UIViewContentMode.ScaleAspectFit
//        imageView.image = self
//        UIGraphicsBeginImageContext(imageView.bounds.size)
//        imageView.layer.renderInContext(UIGraphicsGetCurrentContext()!)
//        let result = UIGraphicsGetImageFromCurrentImageContext()
//        UIGraphicsEndImageContext()
//        return result
//    }

    func resize(newSize:CGSize) -> UIImage {
        // here both true and false seems both work to resize
        //        let hasAlpha = false
        let hasAlpha = true
        let scale:CGFloat = 0.0 //system will auto get the real factor
        
        UIGraphicsBeginImageContextWithOptions(newSize, !hasAlpha, scale)
        
        self.drawInRect(CGRect(origin: CGPointZero, size: newSize))
        
        let resizedImage:UIImage = UIGraphicsGetImageFromCurrentImageContext()
        
        UIGraphicsEndImageContext()
        
        return resizedImage
    }
    
    func resizeToWidth(newWidth:CGFloat) -> UIImage {
        let scale = newWidth / self.size.width
        //print("scale=\(scale)")
        let newHeight = self.size.height * scale
        //print("newHeight=\(newHeight)")
        
        let newSize = CGSize(width: newWidth, height: newHeight)
        
        return self.resize(newSize)
    }
    
    func resizeToHeight(newHeight:CGFloat) -> UIImage {
        let scale = newHeight / self.size.width
        //print("scale=\(scale)")
        let newWidth = self.size.height * scale
        //print("newWidth=\(newWidth)")
        
        let newSize = CGSize(width: newWidth, height: newHeight)
        
        return self.resize(newSize)
    }
    
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
        let vcCount = naviViewControllers.count //3
        let maxVcIdx = vcCount - 1 //3
        let callerVcIdx = maxVcIdx - 1 //2
        if callerVcIdx >= 0 {
            calerVc = naviViewControllers[callerVcIdx]
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

/***************************************************************************
* Table View functions
***************************************************************************/

func hideTableViewCellSeparator(tableViewCell:UITableViewCell) {
    let indentLargeEnoughtToHide:CGFloat = 10000
    // indent large engough for separator(including cell' content) to hidden separator
    tableViewCell.separatorInset = UIEdgeInsetsMake(0, indentLargeEnoughtToHide, 0, 0)
    // adjust the cell's content to show normally
    tableViewCell.indentationWidth = indentLargeEnoughtToHide * -1
    // must add this, otherwise default is 0, now actual indentation = indentationWidth * indentationLevel = 10000 * 1 = -10000
    tableViewCell.indentationLevel = 1
}

func setTableViewCellSeparatorLeftInset0(tableViewCell:UITableViewCell) {
    //make separator left align to edge
    tableViewCell.separatorInset = UIEdgeInsetsZero
    tableViewCell.layoutMargins = UIEdgeInsetsZero
    //tableViewCell.layoutMargins.left = 0
    tableViewCell.preservesSuperviewLayoutMargins = false
}

func setTableViewCellSeparatorBothInset(tableViewCell:UITableViewCell){
    let AllPageLeftRightPadding:CGFloat = 15.0

    tableViewCell.separatorInset = UIEdgeInsetsMake(0, AllPageLeftRightPadding, 0, AllPageLeftRightPadding)
    tableViewCell.layoutMargins = UIEdgeInsetsZero
   // tableViewCell.preservesSuperviewLayoutMargins = false
}

/***************************************************************************
 * Charts Related functions
 * https://github.com/danielgindi/Charts
 ***************************************************************************/

//do common settings for line/bar chart view
func commonLineBarChartViewSettings(curChartView:BarLineChartViewBase) {
    curChartView.noDataText = "暂无数据"
    curChartView.noDataTextDescription = "没有找到有效数据"
    curChartView.dragEnabled = true
    curChartView.setScaleEnabled(true)
    curChartView.drawGridBackgroundEnabled = true
    curChartView.gridBackgroundColor = UIColor.yellowColor()
    curChartView.pinchZoomEnabled = true
    curChartView.drawBordersEnabled = true
    
    if curChartView is BarChartView {
        let curBarChatView = curChartView as! BarChartView
        curBarChatView.drawBarShadowEnabled = false
        curBarChatView.drawHighlightArrowEnabled = true
    }
    
    //curChartView.backgroundColor = UIColor.cyanColor()
    //curChartView.backgroundColor = UIColor.brownColor()
    curChartView.backgroundColor = UIColor.lightTextColor()
    //        curChartView.backgroundColor = UIColor.lightGrayColor()
    //curChartView.backgroundColor = UIColor.purpleColor()
}

//set data for single line chart view
func setSingleLineChart(curLineChartView:LineChartView, xPointList: [String], leftYAXisValues: [Double], leftYAxisLabel:String, lineColor:UIColor = UIColor.redColor()) {
    var leftYDataEntryList: [ChartDataEntry] = []
    
    for i in 0..<xPointList.count {
        let leftYAxisDataEntry = ChartDataEntry(value: leftYAXisValues[i], xIndex: i)
        leftYDataEntryList.append(leftYAxisDataEntry)
    }
    
    let leftYAxisChartDataSet = LineChartDataSet(yVals: leftYDataEntryList, label: leftYAxisLabel)
    leftYAxisChartDataSet.setColor(lineColor)
    
    let leftYAxisChartData = LineChartData(xVals: xPointList, dataSet: leftYAxisChartDataSet)
    curLineChartView.data = leftYAxisChartData
}


//set data for double line chart view
func setDoubleLineChart(curDoubleLineChartView:LineChartView, xPoints: [String], leftAxisValues: [Double], rightAxisValues:[Double], leftAxisLabel:String, rightAxisLabel:String, leftColor:UIColor = UIColor.cyanColor(), rightColor:UIColor = UIColor.redColor()) {
    var leftDataEntrieList: [ChartDataEntry] = []
    var rightDataEntrieList: [ChartDataEntry] = []
    
    for i in 0..<xPoints.count {
        let leftDataEntry = ChartDataEntry(value: leftAxisValues[i], xIndex: i)
        leftDataEntrieList.append(leftDataEntry)
        
        let rightDataEntry = ChartDataEntry(value: rightAxisValues[i], xIndex: i)
        rightDataEntrieList.append(rightDataEntry)
    }
    
    let leftChartDataSet = LineChartDataSet(yVals: leftDataEntrieList, label: leftAxisLabel)
    leftChartDataSet.setColor(leftColor)
    leftChartDataSet.fillColor = leftColor
    leftChartDataSet.setCircleColor(leftColor)
    
    let rightChartDataSet = LineChartDataSet(yVals: rightDataEntrieList, label: rightAxisLabel)
    rightChartDataSet.setColor(rightColor)
    rightChartDataSet.fillColor = rightColor
    rightChartDataSet.setCircleColor(rightColor)
    
    var dataSetList:[LineChartDataSet] = [LineChartDataSet]()
    dataSetList.append(leftChartDataSet)
    dataSetList.append(rightChartDataSet)
    
    //init common settings
    for eachDataSet in dataSetList {
        eachDataSet.drawCircleHoleEnabled = false
        eachDataSet.lineWidth = 1.0
        eachDataSet.circleRadius = 4.0
        eachDataSet.fillAlpha = 65/255.0
    }
    
    let totalChartData = LineChartData(xVals: xPoints, dataSets: dataSetList)
    
    curDoubleLineChartView.data = totalChartData
}

//set data for single bar chart view
func setSingleBarChart(curBarChartView:BarChartView, xPointList: [String], leftYAXisValues: [Double], leftYAxisLabel:String, barColor:UIColor = UIColor.cyanColor()) {
    var leftYDataEntryList: [BarChartDataEntry] = []
    
    for i in 0..<xPointList.count {
        let leftYAxisDataEntry = BarChartDataEntry(value: leftYAXisValues[i], xIndex: i)
        leftYDataEntryList.append(leftYAxisDataEntry)
    }
    
    let leftYAxisChartDataSet = BarChartDataSet(yVals: leftYDataEntryList, label: leftYAxisLabel)
    leftYAxisChartDataSet.setColor(barColor)
    
    let leftYAxisChartData = BarChartData(xVals: xPointList, dataSet: leftYAxisChartDataSet)
    curBarChartView.data = leftYAxisChartData
}

//do common settings for pie chart view
func commomPieChartViewSettings(curPieChartView:PieChartView, centerText:String = "", isValueUsePercent:Bool = true) {
    curPieChartView.descriptionText = ""
    
    curPieChartView.usePercentValuesEnabled = isValueUsePercent
    
    let InnerCirclePaddingPercent:CGFloat = 0.03
    curPieChartView.drawSlicesUnderHoleEnabled = false
    //        curPieChartView.holeRadiusPercent = 0.58
    curPieChartView.holeRadiusPercent = 0.50
    //        curPieChartView.transparentCircleRadiusPercent = 0.61
    curPieChartView.transparentCircleRadiusPercent = curPieChartView.holeRadiusPercent + InnerCirclePaddingPercent
    curPieChartView.setExtraOffsets(left: 5.0, top: 10.0, right: 5.0, bottom: 5.0)
    
    curPieChartView.drawCenterTextEnabled = true
    
    let paraStyle:NSMutableParagraphStyle = NSMutableParagraphStyle()
    paraStyle.alignment = .Center
    paraStyle.lineBreakMode = .ByCharWrapping
    
    let attributedCenterText:NSMutableAttributedString = NSMutableAttributedString(string: centerText)
    attributedCenterText.addAttributes([NSParagraphStyleAttributeName : paraStyle], range: NSMakeRange(0, centerText.characters.count))
    
    curPieChartView.centerText = centerText
    
    curPieChartView.drawHoleEnabled = true
    curPieChartView.rotationAngle = 0.0
    curPieChartView.rotationEnabled = true
    curPieChartView.highlightPerTapEnabled = true
    
    let pieLegend:ChartLegend = curPieChartView.legend
    pieLegend.position = ChartLegend.ChartLegendPosition.RightOfChart
    pieLegend.xEntrySpace = 7.0
    pieLegend.yEntrySpace = 0.0
    pieLegend.yOffset = 0.0
}

//set data for pie chart view
func setPieChart(curPieChartView:PieChartView, xLabelList: [String], yValueList: [Double], label:String) {
    var yDataEntryList: [BarChartDataEntry] = []
    
    for i in 0..<yValueList.count {
        let yDataEntry = BarChartDataEntry(value: yValueList[i], xIndex: i)
        yDataEntryList.append(yDataEntry)
    }
    
    let pieChartDataSet = PieChartDataSet(yVals: yDataEntryList, label: label)
    pieChartDataSet.sliceSpace = 2.0
    //add colors
    pieChartDataSet.colors = ChartColorTemplates.colorful()
    //        pieChartDataSet.colors = ChartColorTemplates.joyful()
    //        pieChartDataSet.colors = ChartColorTemplates.liberty()
    //        pieChartDataSet.colors = ChartColorTemplates.pastel()
    //        pieChartDataSet.colors = ChartColorTemplates.vordiplom()
    
    let pieChartData = PieChartData(xVals: xLabelList, dataSet: pieChartDataSet)
    
    if curPieChartView.usePercentValuesEnabled {
        let numberFormatter:NSNumberFormatter = NSNumberFormatter()
        numberFormatter.numberStyle = NSNumberFormatterStyle.PercentStyle
        numberFormatter.maximumFractionDigits = 1
        numberFormatter.multiplier = 1.0
        numberFormatter.percentSymbol = " %"
        
        pieChartData.setValueFormatter(numberFormatter)
    } else {
        let numberFormatter:NSNumberFormatter = NSNumberFormatter()
        numberFormatter.numberStyle = NSNumberFormatterStyle.NoStyle
        numberFormatter.maximumFractionDigits = 0
        
        pieChartData.setValueFormatter(numberFormatter)
    }
    
    pieChartData.setValueFont(UIFont.systemFontOfSize(11))
    pieChartData.setValueTextColor(UIColor.whiteColor())
    
    curPieChartView.data = pieChartData
    curPieChartView.highlightValues([])
}

