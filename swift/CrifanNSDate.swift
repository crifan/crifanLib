//
//  CrifanNSDate.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit


extension Date {
    @nonobjc static let emptyDate:Date = Date(timeIntervalSince1970: 0)

    @nonobjc static let SecondsPerMinute:Int = 60
    @nonobjc static let MinutesPerHour:Int = 60
    @nonobjc static let HoursPerDay:Int = 24
    
    @nonobjc static let MinutesPerDay:Int = MinutesPerHour * HoursPerDay
    
    @nonobjc static let SecondsPerHour:Int = SecondsPerMinute * MinutesPerHour
    @nonobjc static let SecondsPerDay:Int = SecondsPerHour * HoursPerDay
    
    //2015
    var Year: Int {
        let curCalendar:Calendar = Calendar.current
        let componentYear:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.year, from: self)
        return componentYear
    }
    
    //11
    var Month: Int {
        let curCalendar:Calendar = Calendar.current
        let componentMonth:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.month, from: self)
        return componentMonth
    }
    
    //28
    var Day: Int {
        let curCalendar:Calendar = Calendar.current
        let componentDay:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.day, from: self)
        return componentDay
    }
    
    //10
    var Hour: Int {
        let curCalendar:Calendar = Calendar.current
        let componentHour:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.hour, from: self)
        return componentHour
    }
    
    //39
    var Minute: Int {
        let curCalendar:Calendar = Calendar.current
        let componentMinute:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.minute, from: self)
        return componentMinute
    }
    
    //18
    var Second: Int {
        let curCalendar:Calendar = Calendar.current
        let componentSecond:Int = (curCalendar as NSCalendar).component(NSCalendar.Unit.second, from: self)
        return componentSecond
    }
    
    //get short style date time string
    //11/28/15, 10:51 AM
    func toStringShort() -> String {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateStyle = DateFormatter.Style.short
        dateFormatter.timeStyle = DateFormatter.Style.short
        let shortStyleStr:String = dateFormatter.string(from: self)
        return shortStyleStr
    }
    
    //get medium style date time string
    //Nov 28, 2015, 10:51:33 AM
    func toStringMedium() -> String {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateStyle = DateFormatter.Style.medium
        dateFormatter.timeStyle = DateFormatter.Style.medium
        let mediumStyleStr:String = dateFormatter.string(from: self)
        return mediumStyleStr
    }
    
    //get long style date time string
    //November 28, 2015 at 10:51:33 AM GMT+8
    func toStringLong() -> String {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateStyle = DateFormatter.Style.long
        dateFormatter.timeStyle = DateFormatter.Style.long
        let longStyleStr:String = dateFormatter.string(from: self)
        return longStyleStr
    }
    
    //get full style date time string
    //Saturday, November 28, 2015 at 10:51:33 AM China Standard Time
    func toStringFull() -> String {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateStyle = DateFormatter.Style.full
        dateFormatter.timeStyle = DateFormatter.Style.full
        let fullStyleStr:String = dateFormatter.string(from: self)
        return fullStyleStr
    }
    
    //get date formatted string
    //2015/11/28 10:48:12
    func toString(_ dateFormat:String) -> String {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateFormat = dateFormat
        let formattedDatetimeStr:String = dateFormatter.string(from: self)
        return formattedDatetimeStr
    }
    
    //parse input date time string into NSDate
    //input: 2015/11/28 12:01:02 and yyyy/MM/dd HH:mm:ss
    //output: Optional(2015-11-28 04:01:02 +0000)
    static func fromString(_ datetimeStr:String, dateFormat:String) -> Date? {
        let dateFormatter:DateFormatter = DateFormatter()
        dateFormatter.dateFormat = dateFormat
        let parsedDatetime:Date? = dateFormatter.date(from: datetimeStr)
        return parsedDatetime
    }
    
    //from milli second timestamp to NSDate
    static func fromTimestampMsec(_ timestampInt64InMsec:Int64) -> Date {
        //        print("timestampInt64InMsec=\(timestampInt64InMsec)") //timestampInt64InMsec=1449805150184
        let timestampDoubleInSec:Double = Double(timestampInt64InMsec)/1000
        //        print("timestampDoubleInSec=\(timestampDoubleInSec)") //timestampDoubleInSec=1449805150.184
        let parsedDate:Date = Date(timeIntervalSince1970: TimeInterval(timestampDoubleInSec))
        //        print("parsedDate=\(parsedDate)") //parsedDate=2015-12-11 03:39:10 +0000
        
        return parsedDate
    }
    
    //convert time to Int64 timestamp:
    //-> in millisecond -> 13 digits: 1466576142336
    //-> in second      -> 10 digits: 1466576128
    func toTimestamp(_ toMilliSec:Bool = true) -> Int64 {
        var curTimestamp:Int64 = 0
        
        //print("self=\(self)")
        //print("self.timeIntervalSince1970=\(self.timeIntervalSince1970)")
        //1466576025.00243
        
        var curTimestampFloat = Float(self.timeIntervalSince1970)
        //print("curTimestampFloat=\(curTimestampFloat)")
        
        if toMilliSec {
            curTimestampFloat = curTimestampFloat * 1000
            //print("timestampFloat=\(curTimestampFloat)")
        }
        
        curTimestamp = Int64(curTimestampFloat)
        //print("curTimestamp=\(curTimestamp)")
        //1466576025002
        //1466576025
        
        print("\(self) -> \(curTimestamp)")
        
        return curTimestamp
    }
    
    //convert time to Int64 timestamp:
    //-> in second      -> 10 digits: 1466576128
    func toTimestampInSec() -> Int64 {
        return self.toTimestamp(false)
    }
    
    func isSameDay(_ dateToCmp:Date) -> Bool {
        var isSameDay = false
        
        if  (self.Year == dateToCmp.Year) &&
            (self.Month == dateToCmp.Month) &&
            (self.Day == dateToCmp.Day) {
            isSameDay = true
        }
        
        print("self=\(self), dateToCmp=\(dateToCmp) -> isSameDay=\(isSameDay)")
        
        return isSameDay
    }
    
    var yesterday: Date {
        let yesterday = self.addingTimeInterval(TimeInterval(-Date.SecondsPerDay))
        print("yesterday=\(yesterday)")
        
        return yesterday
    }
    
    var dayBeforeYesterday: Date {
        let yesterday = self.yesterday
        print("yesterday=\(yesterday)")
        let theDayBeforeyesterday = yesterday.yesterday
        print("theDayBeforeyesterday=\(theDayBeforeyesterday)")
        
        return theDayBeforeyesterday
    }
    
    func daysBefore(_ days:Int) -> Date {
        return daysAfter(-days)
    }
    
    func daysAfter(_ days:Int) -> Date {
        let secondsForDays = Date.SecondsPerDay * days
        return self.addingTimeInterval(TimeInterval(secondsForDays))
    }
    
    var isToday: Bool {
        print("self=\(self)")
        
        let curDate = Date()
        let sameWithToday = self.isSameDay(curDate)
        
        print("self=\(self) -> sameWithToday=\(sameWithToday)")
        
        return sameWithToday
    }
    
    var isYesterday: Bool {
        print("self=\(self)")
        //self=2016-06-28 07:27:04 +0000
        
        let curDate = Date()
        
        let yesterday = curDate.yesterday
        print("yesterday=\(yesterday)")
        
        let sameWithYesterday = self.isSameDay(yesterday)
        
        print("self=\(self) -> sameWithYesterday=\(sameWithYesterday)")
        //self=2016-06-28 07:27:04 +0000 -> isyesterday=true
        
        return sameWithYesterday
    }
    
    //is the Day Before yesterday == 前天
    var isDayBeforeYesterday: Bool {
        //Day Before Yesterday
        var isDBY = false
        
        let curDate = Date()
        let dayBeforeYesterday = curDate.dayBeforeYesterday
        
        isDBY = dayBeforeYesterday.isSameDay(self)
        
        print("self=\(self) -> isDBY=\(isDBY)")
        
        return isDBY
    }
    func timeToString(_ useRelativeDay:Bool = false) -> String {
        
        let curDate = Date()
        
        //print("self=\(self), curDate=\(curDate)")
        //self=2016-06-28 07:07:36 +0000, curDate=2016-06-29 03:27:23 +0000
        
        var components = self.toDateComponents(curDate)
        //print("components=\(components)")
        
        /*
         <NSDateComponents: 0x7a732ae0>
         Calendar Year: 0
         Month: 0
         Day: 0
         Hour: 20
         Minute: 19
         Second: 47
         */
        
        if useRelativeDay {
            //if use relative day, not use absolute diff time
            //so need correct for some special day
            switch components.day {
            case 0?, 1?, 2?, 3?, 7?, 14?:
                let daysBefore = components.day! + 1
                let dateDaysBefore = curDate.daysBefore(daysBefore)
                //print("components.day=\(components.day), curDate=\(curDate), dateDaysBefore=\(dateDaysBefore), self=\(self)")
                if self.isSameDay(dateDaysBefore) {
                    components.day = daysBefore
                }
            default:
                break
            }
        }
        
        if components.year! > 0 {
            
            let timeFormat = "YY/M/d"
            return  self.toString(timeFormat)
        }
        
        if components.month! > 0 {
            
            let timeFormat = "M/d"
            return  self.toString(timeFormat)
        }
        
        if components.day! > 0 {
            if components.day == 1 {
                return "昨天"
            } else {
                let timeFormat = "M/d"
                return  self.toString(timeFormat)
            }
            
        } else if components.day == 0 {
            return "今天"
        }
        
        return ""
    }
    
    func toAgoString(_ useRelativeDay:Bool = false, agoInDigit:Bool = false) -> String {
        let curDate = Date()
        
        //print("self=\(self), curDate=\(curDate)")
        //self=2016-06-28 07:07:36 +0000, curDate=2016-06-29 03:27:23 +0000
        
        var components = self.toDateComponents(curDate)
        //print("components=\(components)")
        
        /*
         <NSDateComponents: 0x7a732ae0>
         Calendar Year: 0
         Month: 0
         Day: 0
         Hour: 20
         Minute: 19
         Second: 47
         */
        
        if useRelativeDay {
            //if use relative day, not use absolute diff time
            //so need correct for some special day
            switch components.day {
            case 0?, 1?, 2?, 3?, 7?, 14?:
                let daysBefore = components.day! + 1
                let dateDaysBefore = curDate.daysBefore(daysBefore)
                //print("components.day=\(components.day), curDate=\(curDate), dateDaysBefore=\(dateDaysBefore), self=\(self)")
                if self.isSameDay(dateDaysBefore) {
                    components.day = daysBefore
                }
            default:
                break
            }
        }
        
        if components.year! > 0 {
            if agoInDigit {
                return "1年前"
            } else {
                return "一年前"
            }
        }
        
        if components.month! > 0 {
            if (components.month! >= 6) && (components.month! < 12) {
                return "半年前"
            } else if (components.month! >= 3) && (components.month! < 6) {
                if agoInDigit {
                    return "3个月前"
                } else {
                    return "三个月前"
                }
            } else if (components.month! >= 1) && (components.month! < 3) {
                if agoInDigit {
                    return "1个月前"
                } else {
                    return "一月前"
                }
            }
        }
        
        if components.day! > 0 {
            if components.day! >= 14 {
                if agoInDigit {
                    return "2周前"
                } else {
                    return "两周前"
                }
            } else if (components.day! >= 7) && (components.day! < 14) {
                if agoInDigit {
                    return "1周前"
                } else {
                    return "一周前"
                }
            } else if (components.day! >= 3) && (components.day! < 7) {
                if agoInDigit {
                    return "3天前"
                } else {
                    return "三天前"
                }
                //} else if (components.day > 1) && (components.day < 3) {
            } else if components.day == 2 {
                if agoInDigit {
                    return "2天前"
                } else {
                    return "两天前"
                }
            } else if components.day == 1 {
                return "昨天"
            }
        } else if components.day == 0 {
            return "今天"
        }
        
        return ""
    }
    
    func toDateComponents(_ toDate:Date) -> DateComponents {
        let calander = Calendar.current
        return (calander as NSCalendar).components([.second, .minute, .hour, .day, .month, .year], from: self, to: toDate, options: [])
    }
    
}

public func <(lhs: Date, rhs: Date) -> Bool {
    return lhs.compare(rhs) == .orderedAscending
}

//extension Date: Comparable { }
