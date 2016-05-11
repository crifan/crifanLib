//
//  CrifanLibDemo.swift
//  Crifan
//
//  Created by licrifan on 15/11/20.
//  Copyright © 2016年 licrifan. All rights reserved.
//
//  Last Update: 2016-05-11

import UIKit

//unuseful function CrifanLibDemo, just for demo usage for CrifanLib
func CrifanLibDemo(){
    
    //TODO: add remaing function demo to here

    /*
    * splitSingleStrToStrArr demo
    */
    let singleStr:String = "张三"
    let firstCharStr:String = getFirstChar(singleStr)
    print("firstCharStr=\(firstCharStr)") //张
    
    /*
    * getLastChar demo
    */
    let singleStr2:String = "张三"
    let lastCharStr:String = getLastChar(singleStr2)
    print("lastCharStr=\(lastCharStr)") //三
    
    /*
    * splitSingleStrToCharArr demo
    */
    let stringToSplit:String = "一个字符串"
    let spiltedCharArr:[Character] = splitSingleStrToCharArr(stringToSplit)
    print("spiltedCharArr=\(spiltedCharArr)") //["一", "个", "字", "符", "串"]

    /*
    * splitSingleStrToStrArr demo
    */
    let noneSeperatorStr:String = ""
    let strWithoutSpace:String = "中间没有空格单个字符串"
    let splitedStrArr_withoutSpace:[String] = splitSingleStrToStrArr(strWithoutSpace, seperatorStr: noneSeperatorStr)
    print("splitedStrArr_withoutSpace=\(splitedStrArr_withoutSpace)") //["中", "间", "没", "有", "空", "格", "单", "个", "字", "符", "串"]

    let spaceSeperatorStr:String = " "
    let stringContainingSpace:String = "中 间   有  空     格 的 字   符 串 "
    let splitedStrArr_containingSpace:[String] = splitSingleStrToStrArr(stringContainingSpace, seperatorStr: spaceSeperatorStr)
    print("splitedStrArr_containingSpace=\(splitedStrArr_containingSpace)") //["中", "间", "有", "空", "格", "的", "字", "符", "串"]


    /*
    * mergeCharArrToSingleStr demo
    */
    let charArrToMerge:[Character] = ["待", "合", "并", "字", "符", "数", "组"]
    let mergedStr:String = mergeCharArrToSingleStr(charArrToMerge)
    print("mergedStr=\(mergedStr)") //"待合并字符数组"

    /*
    * mergeStrArrToSingleStr demo
    */
    let stringArrToMerge:[String] = ["待", "合", "并", "字", "符", "串","数", "组"]
    let mergedSingleStr:String = mergeStrArrToSingleStr(stringArrToMerge)
    print("mergedSingleStr=\(mergedSingleStr)") //"待合并字符串数组"

    /*
    * translateChineseStrToPinyinWithAccents demo
    */
    let chineseStr:String = "昂山素季"
    let translatedPinyinStrWithAccents:String = translateChineseStrToPinyinWithAccents(chineseStr)
    print("translatedPinyinStrWithAccents=\(translatedPinyinStrWithAccents)") //"áng shān sù jì"

    /*
    * removeAccentsFromStr demo
    */
    let pinyinWithAccents:String = "áng shān sù jì"
    let strippedAccentsPinyin:String = removeAccentsFromStr(pinyinWithAccents)
    print("strippedAccentsPinyin=\(strippedAccentsPinyin)") //"ang shan su ji"

    /*
    * translateChineseStrToCharPinyinDict demo
    */
    let chineseStrToTranslate:String = "昂山素季"
    let translatedCharPinyinDict = translateChineseStrToCharPinyinDict(chineseStrToTranslate)
    print("translatedCharPinyinDict=\(translatedCharPinyinDict)") //[["昂": "ang"], ["山": "shan"], ["素": "su"], ["季": "ji"]]

    
    /*
    * NSdate extension demo
    */
    let curDate:NSDate = NSDate()
    print("curDate=\(curDate)") //2015-11-28 02:35:19 +0000
    print("curDate.Year()=\(curDate.Year())") //2015
    print("curDate.Month()=\(curDate.Month())") //11
    print("curDate.Day()=\(curDate.Day())") //28
    print("curDate.Hour()=\(curDate.Hour())") //10
    print("curDate.Minute()=\(curDate.Minute())") //39
    print("curDate.Second()=\(curDate.Second())") //18
    
    print("curDate.toShortStyleString()=\(curDate.toStringShort())") //11/28/15, 11:04 AM
    print("curDate.toMediumStyleString()=\(curDate.toStringMedium())") //Nov 28, 2015, 11:04:39 AM
    print("curDate.toLongStyleString()=\(curDate.toStringLong())") //November 28, 2015 at 11:04:39 AM GMT+8
    print("curDate.toFullStyleString()=\(curDate.toStringFull())") //Saturday, November 28, 2015 at 11:04:39 AM China Standard Time
    
    let formatedDateStr:String = curDate.toString("yyyy/MM/dd HH:mm:ss") //2015/11/28 11:00:33
    print("formatedDateStr=\(formatedDateStr)")
    
    let parsedDatetime:NSDate? = NSDate.fromString("2015/11/28 12:01:02", dateFormat: "yyyy/MM/dd HH:mm:ss")
    print("parsedDatetime=\(parsedDatetime)") //Optional(2015-11-28 04:01:02 +0000)

    /*
    * fromTimestampMsec demo
    */

    let timestamp1IntInMsec:Int64 = 1449805150184
    let timestamp2IntInMsec:Int64 = 1449605150184
    let timestamp3IntInMsec:Int64 = 1449605150184
    
    let timestamp1 = NSDate.fromTimestampMsec(timestamp1IntInMsec)
    let timestamp2 = NSDate.fromTimestampMsec(timestamp2IntInMsec)
    let timestamp3 = NSDate.fromTimestampMsec(timestamp3IntInMsec)
    /*
    timestamp1=2015-12-11 03:39:10 +0000
    timestamp2=2015-12-08 20:05:50 +0000
    timestamp3=2015-12-08 20:05:50 +0000
    */

    /*
    * NSDate Comparable demo
    */
    print("timestamp1 > timestamp2=\(timestamp1 > timestamp2)")
    print("timestamp1 < timestamp2=\(timestamp1 < timestamp2)")
    
    print("timestamp1 == timestamp2=\(timestamp1 == timestamp2)")
    print("timestamp3 == timestamp2=\(timestamp3 == timestamp2)")
    
    print("timestamp1 <= timestamp2=\(timestamp1 <= timestamp2)")
    print("timestamp1 >= timestamp2=\(timestamp1 >= timestamp2)")
    
    print("timestamp3 <= timestamp2=\(timestamp3 <= timestamp2)")
    print("timestamp3 >= timestamp2=\(timestamp3 >= timestamp2)")
    
    /*
    timestamp1 > timestamp2=true
    timestamp1 < timestamp2=false
    timestamp1 == timestamp2=false
    timestamp3 == timestamp2=true
    timestamp1 <= timestamp2=false
    timestamp1 >= timestamp2=true
    timestamp3 <= timestamp2=true
    timestamp3 >= timestamp2=true
    */


    
    var curSizeInBytes:Int64 = 0
    
    curSizeInBytes = 678 //678 B
    curSizeInBytes = 10002 //9.77 KB
    curSizeInBytes = 1023 * 1024 * 877 //876.14 MB
    curSizeInBytes = 1022 * 1026 * 1022 * 387 //386.24 GB
    curSizeInBytes = 1012 * 1036 * 1042 * 1024 * 102 //103.78 TB
    curSizeInBytes = 1012 * 1036 * 1042 * 1024 * 1024 * 3400 //3459.29 PB
    
    genSizeStr(curSizeInBytes)
}



