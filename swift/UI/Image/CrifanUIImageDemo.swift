//
//  CrifanUIImageDemo.swift
//  Xxx
//
//  Created by licrifan on 16/7/16.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

class CrifanUIImageDemo {
    
    init() {
        let ButtonNumberPerLine:Int = 3
        let ButtonWidthPercent:Float = 2.0/3.0
        let circleRadius:CGFloat = (UIScreen.mainScreen().bounds.width/CGFloat(ButtonNumberPerLine)) * CGFloat(ButtonWidthPercent)
        
        let darkerBlueColor = UIColor(red: 2.0/255.0, green: 174.0/255.0, blue: 240.0/255.0, alpha: 1)
        let lightBlueColor:UIColor = UIColor(red: 30.0/255.0, green: 175.0/255.0, blue: 235.0/255.0, alpha: 0.3)
        
        //        let borderWidth:CGFloat = 2
        let borderWidth:CGFloat = 3
        let innerCircleRadius:CGFloat = circleRadius/4
        
        let normalGestureNodeImage = drawCircleImage(circleRadius, fillColor: UIColor.clearColor(), borderColor: UIColor.whiteColor(), borderWidth: borderWidth)
        print("normalGestureNodeImage=\(normalGestureNodeImage)")
        
        let selectedCircleImage:UIImage = drawCircileImageWithInnderCircle(circleRadius, fillColor: lightBlueColor, borderColor: darkerBlueColor, borderWidth: borderWidth, innerCircleRadius: innerCircleRadius, innerCircleFillColor: darkerBlueColor)
        let selectedGestureNodeImage = selectedCircleImage
        print("selectedGestureNodeImage=\(selectedGestureNodeImage)")
        

    }
/*
    //draw single header image with text label
    func drawSingleCornerHeaderImageWithLabel(headerLabelString:String,  headerLabelFont:UIFont, headerImageSize:CGFloat, backgroundColor:UIColor) -> UIImage {
        let rectHeaderImage:UIImage = drawRectHeaderImageWithLabel(headerLabelString, headerLabelFont: headerLabelFont, headerImageSize: headerImageSize, backgroundColor: backgroundColor)
        
        let cornerHeaderImage = drawCornerImage(rectHeaderImage, cornerRadius: SizeHeaderImageCornerRadius)
        
        return cornerHeaderImage
    }
     
     self.badgeView = drawBadgeView(realBadgeStr, badgeRadius: self.badgeRadius, circleFillColor: self.badgeFillColor, badgeFont: self.badgeFont)
     
     let backgroundRectImage:UIImage = drawRectangleImage(
     CGSizeMake(headerImageSize, headerImageSize),
     color: backgroundColor)
     
//draw single header image with custom image
//makesure align center for custom image
func drawSingleCornerHeaderImageWithImage(customImage:UIImage, headerImageSize:CGFloat, backgroundColor:UIColor) -> UIImage {
    
    let backgroundRectImage:UIImage = drawRectangleImage(
        CGSizeMake(headerImageSize, headerImageSize),
        color: backgroundColor)
    
    var toMergeImageArr:[UIImage] = Array<UIImage>()
    toMergeImageArr.append(backgroundRectImage)
    toMergeImageArr.append(customImage)

    var drawPointArr:[CGPoint] = [CGPoint]()
    drawPointArr.append(CGPoint(x: 0, y: 0))
    drawPointArr.append(CGPoint(
        x: (headerImageSize - customImage.size.width) / 2,
        y: (headerImageSize - customImage.size.height) / 2))

//    let mergedRectHeaderImage:UIImage = mergeMultipleToSingleImage(backgroundRectImage, imageArr: toMergeImageArr, drawPointArr: drawPointArr)
    let mergedRectHeaderImage:UIImage = mergeMultipleToSingleImage(backgroundRectImage.size, imageArr: toMergeImageArr, drawPointArr: drawPointArr)
    
    let roundCornerHeaderImage:UIImage = drawCornerImage(
        mergedRectHeaderImage,
        cornerRadius: SizeHeaderImageCornerRadius)
    
    return roundCornerHeaderImage
}
     
     
     
     let resizedHeaderImage:UIImage = eachOrigHeaderImage.resizeToWidth(headImageSize)
     
     
     self.pickedItem.scaledImage = self.pickedItem.originImage.compressImage(AttachmentMaxImageSize)

     let scaledImageData = self.pickedItem.scaledImage.toJpegData(0.8)
 */

}
