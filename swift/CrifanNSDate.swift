//
//  CrifanNSDate.swift
//  SalesApp
//
//  Created by licrifan on 16/6/21.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit



extension NSDate
{
    //2015
    var Year: Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentYear:Int = curCalendar.component(NSCalendarUnit.Year, fromDate: self)
        return componentYear
    }
    
    //11
    var Month: Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentMonth:Int = curCalendar.component(NSCalendarUnit.Month, fromDate: self)
        return componentMonth
    }
    
    //28
    var Day: Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentDay:Int = curCalendar.component(NSCalendarUnit.Day, fromDate: self)
        return componentDay
    }
    
    //10
    var Hour: Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentHour:Int = curCalendar.component(NSCalendarUnit.Hour, fromDate: self)
        return componentHour
    }
    
    //39
    var Minute: Int {
        let curCalendar:NSCalendar = NSCalendar.currentCalendar()
        let componentMinute:Int = curCalendar.component(NSCalendarUnit.Minute, fromDate: self)
        return componentMinute
    }
    
    //18
    var Second: Int {
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
    //    var emptyDate:NSDate {
    //        return NSDate(timeIntervalSince1970: 0)
    //    }
    @nonobjc static let emptyDate:NSDate = NSDate(timeIntervalSince1970: 0)
    
    func isToday(toCmpTime:NSDate) -> Bool {
        var isToday = false
        
        if (toCmpTime.Year == self.Year) &&
            (toCmpTime.Month == self.Month) &&
            (toCmpTime.Day == self.Day) {
            isToday = true
        }
        
        return isToday
    }
    
    func toAgoString() -> String {
        let curDate = NSDate()
        
        print("self=\(self), curDate=\(curDate)")
        
        let components = self.toDateComponents(curDate)
        
        print("components.year=\(components.year), components.month=\(components.month)")
        
        if components.year > 0 {
            //            if (components.year >= 1) {
            return "一年前"
            //            }
        }
        
        if components.month > 0 {
            if (components.month >= 6) && (components.month < 12) {
                return "半年前"
            } else if (components.month >= 3) && (components.month < 6) {
                //return "三个月前"
                return "3个月前"
            } else if (components.month >= 1) && (components.month < 3) {
                //return "一个月前"
                return "1个月前"
            }
        }
        
        if components.day > 0 {
            if components.day >= 14 {
                //return "两周前"
                return "2周前"
            } else if (components.day >= 7) && (components.day < 14) {
                //return "一周前"
                return "1周前"
            } else if (components.day >= 3) && (components.day < 7) {
                //return "三天前"
                return "3天前"
            } else if (components.day > 1) && (components.day < 3) {
                //return "一天前"
                return "1天前"
            } else if components.day == 1 {
                return "昨天"
            }
        } else if components.day == 0 {
            return "今天"
        }
        
        return ""
    }
    
    func toDateComponents(toDate:NSDate) -> NSDateComponents {
        let calander = NSCalendar.currentCalendar()
        return calander.components([.Second, .Minute, .Hour, .Day, .Month, .Year], fromDate: self, toDate: toDate, options: [])
    }
    
}


public func ==(lhs: NSDate, rhs: NSDate) -> Bool {
    return lhs === rhs || lhs.compare(rhs) == .OrderedSame
}

public func <(lhs: NSDate, rhs: NSDate) -> Bool {
    return lhs.compare(rhs) == .OrderedAscending
}

extension NSDate: Comparable { }