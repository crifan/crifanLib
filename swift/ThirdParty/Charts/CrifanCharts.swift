//
//  CrifanCharts.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit
import Charts //https://github.com/danielgindi/Charts

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



