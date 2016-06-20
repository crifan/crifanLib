//
//  CrifanLibUI.swift
//  SalesApp
//
//  Created by licrifan on 16/6/7.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography
import Charts //https://github.com/danielgindi/Charts


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

//draw a circle image with border, if border is 0 means no border
func drawCircleImage(circleRadius:CGFloat, fillColor:UIColor = UIColor.blueColor(), borderColor:UIColor = UIColor.cyanColor(), borderWidth:CGFloat = 0) -> UIImage {
    UIGraphicsBeginImageContextWithOptions(CGSize(width: circleRadius, height: circleRadius), false, 0)
    let context = UIGraphicsGetCurrentContext()
    
    let rectangle = CGRectMake(borderWidth, borderWidth, circleRadius - borderWidth - 1, circleRadius - borderWidth - 1)
    
    CGContextSetFillColorWithColor(context, fillColor.CGColor)
    CGContextSetStrokeColorWithColor(context, borderColor.CGColor)
    CGContextSetLineWidth(context, borderWidth)
    
    CGContextAddEllipseInRect(context, rectangle)
    if borderWidth == 0 {
        CGContextDrawPath(context, .Fill)
    } else {
        CGContextDrawPath(context, .FillStroke)
    }
    
    let circleImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return circleImage
}

//draw a outer big circle with border while inside is a inner small circle filled with color
func drawCircileImageWithInnderCircle(circleRadius:CGFloat, fillColor:UIColor = UIColor.blueColor(), borderColor:UIColor = UIColor.cyanColor(), borderWidth:CGFloat = 0, innerCircleRadius:CGFloat, innerCircleFillColor:UIColor = UIColor.greenColor()) -> UIImage {
    
    UIGraphicsBeginImageContextWithOptions(CGSize(width: circleRadius, height: circleRadius), false, 0)
    let context = UIGraphicsGetCurrentContext()
    
    let rectangle = CGRectMake(borderWidth, borderWidth, circleRadius - borderWidth - 1, circleRadius - borderWidth - 1)
    
    CGContextSetFillColorWithColor(context, fillColor.CGColor)
    CGContextSetStrokeColorWithColor(context, borderColor.CGColor)
    CGContextSetLineWidth(context, borderWidth)
    
    CGContextAddEllipseInRect(context, rectangle)
    if borderWidth == 0 {
        CGContextDrawPath(context, .Fill)
    } else {
        CGContextDrawPath(context, .FillStroke)
    }
    
    let innerRectangle = CGRectMake(circleRadius/2 - innerCircleRadius/2 + 1, circleRadius/2 - innerCircleRadius/2 + 1, innerCircleRadius, innerCircleRadius)
    CGContextSetFillColorWithColor(context, innerCircleFillColor.CGColor)
    CGContextAddEllipseInRect(context, innerRectangle)
    CGContextDrawPath(context, .Fill)
    
    let circleImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return circleImage
}


//draw a badge view
func drawBadgeView(badgeString:String, badgeRadius:CGFloat = 8.5, circleFillColor:UIColor = UIColor.redColor(), badgeFont:UIFont = UIFont.systemFontOfSize(11)) -> UIView {
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
    badgeLabel.font = badgeFont
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
//Note: for round circle image, seems can not merge !
func mergeMultipleToSingleImage(mergedFrameSize: CGSize, imageArr:[UIImage], drawPointArr: [CGPoint]) -> UIImage {
    var mergedImage:UIImage = UIImage()
    let opaque:Bool = false
    let scale:CGFloat = 0
    
    UIGraphicsBeginImageContextWithOptions(mergedFrameSize, opaque, scale)
    
    //Note: while count==0 will crash for 0 can not smaller than 0 - 1 = -1
    //for index in 0...(imageArr.count - 1)
    for index in 0..<imageArr.count {
        let curDrawPoint = drawPointArr[index]
        let curImage = imageArr[index]
        print("[\(index)] curDrawPoint=\(curDrawPoint), curImage=\(curImage)")
        curImage.drawAtPoint(curDrawPoint, blendMode: CGBlendMode.Normal, alpha: 1.0)
    }
    
    mergedImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return mergedImage
}

extension UIImage {
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
 * Table View functions
 ***************************************************************************/

extension UITableViewCell {
    func hideSeparator() {
        let indentLargeEnoughToHide:CGFloat = 10000
        // indent large engough for separator(including cell' content) to hidden separator
        self.separatorInset = UIEdgeInsetsMake(0, indentLargeEnoughToHide, 0, 0)
        // adjust the cell's content to show normally
        self.indentationWidth = indentLargeEnoughToHide * -1
        // must add this, otherwise default is 0, now actual indentation = indentationWidth * indentationLevel = 10000 * 1 = -10000
        self.indentationLevel = 1
    }
    
/*
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
*/
    
    //make separator left align to edge
    func setSeparatorLeftAlign() {
        self.setSeparatorLeftRightAlign(0)

        self.preservesSuperviewLayoutMargins = false
    }
    
    func setSeparatorLeftRightAlign(leftAlign:CGFloat = 0, rightAlign:CGFloat = 0){
        self.separatorInset = UIEdgeInsetsMake(0, leftAlign, 0, rightAlign)
        self.layoutMargins = UIEdgeInsetsZero
        // tableViewCell.preservesSuperviewLayoutMargins = false
    }
    
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



