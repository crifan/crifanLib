//
//  CrifanLibDemo.swift
//  Crifan
//
//  Created by licrifan on 15/11/20.
//  Copyright © 2016年 licrifan. All rights reserved.
//
//  Last Update: 2016-05-16

import UIKit

//https://github.com/danielgindi/Charts
import Charts

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
    
    print("NSDate(timeIntervalSince1970: 0).isEqualToDate(NSDate.emptyDate=\(NSDate(timeIntervalSince1970: 0).isEqualToDate(NSDate.emptyDate)))")

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
    
    
    /*
     * demo for Charts library
     */
    var doubleLineChartView:LineChartView = LineChartView()
    var singleLineChartView:LineChartView = LineChartView()
    var singleBarChartView:BarChartView = BarChartView()
    var pieChartView:PieChartView = PieChartView()

    let dayList:[String] = ["5月16日", "5月17日", "5月18日", "5月19日", "5月20日", "5月21日", "5月22日"]
    let entranceGuestNumList:[Double] = [3, 4, 8, 13, 25, 19, 32]
    let potentialGuestNumList:[Double] = [3, 7, 15, 19, 30, 31, 40]
    
    func initEntranceGuestChartView() {
        commonLineBarChartViewSettings(doubleLineChartView)
        
        //entranceGuestChartView.delegate = self
        doubleLineChartView.descriptionText = "到店流量和潜客统计数据"
        
        //double x axis
        let xAxis:ChartXAxis = doubleLineChartView.xAxis
        xAxis.drawAxisLineEnabled = false
        xAxis.drawGridLinesEnabled = false
        //        xAxis.labelFont = UIFont.systemFontOfSize(12)
        //        xAxis.labelTextColor = UIColor.whiteColor()
        //        xAxis.spaceBetweenLabels = 1.0
        
        let leftColor:UIColor = UIColor.cyanColor()
        //        let leftColor:UIColor = UIColor.blueColor()
        //        let leftColor:UIColor = UIColor.purpleColor()
        //        let leftColor:UIColor = UIColor.magentaColor()
        //        let leftColor:UIColor = UIColor.greenColor()
        let leftAxis:ChartYAxis = doubleLineChartView.leftAxis
        leftAxis.labelTextColor = leftColor
        //        leftAxis.axisMaxValue = 100.0
        leftAxis.axisMinValue = 0.0
        leftAxis.drawGridLinesEnabled = true
        leftAxis.drawZeroLineEnabled = false
        leftAxis.granularityEnabled = true
        
        let rightColor:UIColor = UIColor.redColor()
        let rightAxis:ChartYAxis = doubleLineChartView.rightAxis
        rightAxis.labelTextColor = rightColor
        //        rightAxis.axisMaxValue = 100.0
        rightAxis.axisMinValue = 0.0
        rightAxis.drawGridLinesEnabled = false
        rightAxis.granularityEnabled = false
        
        setDoubleLineChart(doubleLineChartView, xPoints: dayList, leftAxisValues: potentialGuestNumList, rightAxisValues: entranceGuestNumList, leftAxisLabel: "到店流量", rightAxisLabel: "到店潜客", leftColor: leftColor, rightColor: rightColor)
    }
    
    func initPotentialGuestChartView() {
        commonLineBarChartViewSettings(singleLineChartView)
        
        //potentialGuestChartView.delegate = self
        singleLineChartView.descriptionText = "到店潜客统计数据"
        
        //single x axis
        singleLineChartView.leftAxis.enabled = true
        singleLineChartView.rightAxis.enabled = false
        
        setSingleLineChart(singleLineChartView, xPointList: dayList, leftYAXisValues: potentialGuestNumList, leftYAxisLabel: "到店潜客")
    }
    
    func iniFlowGuestChartView() {
        commonLineBarChartViewSettings(singleBarChartView)
        
        //flowGuestChartView.delegate = self
        singleBarChartView.descriptionText = "到店流量统计数据"
        
        singleBarChartView.leftAxis.enabled = true
        singleBarChartView.rightAxis.enabled = false
        
        setSingleBarChart(singleBarChartView, xPointList: dayList, leftYAXisValues: entranceGuestNumList, leftYAxisLabel: "到店流量")
    }
    
    func initDealWithGuestChartView() {
        let dealTypeList:[String] = ["进入未跟进", "进入跟进未成交", "跟进且成交"]
        let diffDealTypeNumList:[Double] = [5, 19, 26]
        
        let labelStr = "成交客户比例统计"
        commomPieChartViewSettings(pieChartView, centerText: labelStr)
        //commomPieChartViewSettings(dealWithGuestChartView, centerText: labelStr, isValueUsePercent: false)
        
        //dealWithGuestChartView.delegate = self
        
        setPieChart(pieChartView, xLabelList: dealTypeList, yValueList: diffDealTypeNumList, label: labelStr)
    }
    
}
