//
//  CrifanUIImage.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import Foundation

/***************************************************************************
 * Drawing Rectangle/Circle/Image Related functions
 ***************************************************************************/

//draw a circle fill with color
func drawCircleLayer(_ circleRadius:CGFloat, fillColor:UIColor) -> CAShapeLayer {
    let circlePath = UIBezierPath(
        arcCenter: CGPoint(x: circleRadius,y: circleRadius),
        radius: circleRadius,
        startAngle: CGFloat(0),
        endAngle:CGFloat(M_PI * 2),
        clockwise: true)
    
    let circleLayer = CAShapeLayer()
    circleLayer.path = circlePath.cgPath
    
    //circle inside fill color
    circleLayer.fillColor = fillColor.cgColor
    //        //set circle line color
    //        circleLayer.strokeColor = UIColor.yellowColor().CGColor
    //        //set circle line width
    //        circleLayer.lineWidth = 3.0
    
    return circleLayer
}

//draw a circle view
func drawCircle(_ circleRadius:CGFloat, fillColor:UIColor) -> UIView {
    //    let circleRadius:CGFloat = 4
    let circleFrame = CGRect(x: 0, y: 0, width: circleRadius * 2, height: circleRadius * 2)
    
    let circleView = UIView(frame: circleFrame)
    let circleLayer = drawCircleLayer(circleRadius, fillColor: fillColor)
    circleView.layer.addSublayer(circleLayer)
    return circleView
}

//draw a circle image with border, if border is 0 means no border
func drawCircleImage(_ circleRadius:CGFloat, fillColor:UIColor = UIColor.blue, borderColor:UIColor = UIColor.cyan, borderWidth:CGFloat = 0) -> UIImage {
    UIGraphicsBeginImageContextWithOptions(CGSize(width: circleRadius, height: circleRadius), false, 0)
    let context = UIGraphicsGetCurrentContext()
    
    let rectangle = CGRect(x: borderWidth, y: borderWidth, width: circleRadius - borderWidth - 1, height: circleRadius - borderWidth - 1)
    
    context?.setFillColor(fillColor.cgColor)
    context?.setStrokeColor(borderColor.cgColor)
    context?.setLineWidth(borderWidth)
    
    context?.addEllipse(in: rectangle)
    if borderWidth == 0 {
        context?.drawPath(using: .fill)
    } else {
        context?.drawPath(using: .fillStroke)
    }
    
    let circleImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return circleImage!
}

//draw a outer big circle with border while inside is a inner small circle filled with color
func drawCircileImageWithInnderCircle(_ circleRadius:CGFloat, fillColor:UIColor = UIColor.blue, borderColor:UIColor = UIColor.cyan, borderWidth:CGFloat = 0, innerCircleRadius:CGFloat, innerCircleFillColor:UIColor = UIColor.green) -> UIImage {
    
    UIGraphicsBeginImageContextWithOptions(CGSize(width: circleRadius, height: circleRadius), false, 0)
    let context = UIGraphicsGetCurrentContext()
    
    let rectangle = CGRect(x: borderWidth, y: borderWidth, width: circleRadius - borderWidth - 1, height: circleRadius - borderWidth - 1)
    
    context?.setFillColor(fillColor.cgColor)
    context?.setStrokeColor(borderColor.cgColor)
    context?.setLineWidth(borderWidth)
    
    context?.addEllipse(in: rectangle)
    if borderWidth == 0 {
        context?.drawPath(using: .fill)
    } else {
        context?.drawPath(using: .fillStroke)
    }
    
    let innerRectangle = CGRect(x: circleRadius/2 - innerCircleRadius/2 + 1, y: circleRadius/2 - innerCircleRadius/2 + 1, width: innerCircleRadius, height: innerCircleRadius)
    context?.setFillColor(innerCircleFillColor.cgColor)
    context?.addEllipse(in: innerRectangle)
    context?.drawPath(using: .fill)
    
    let circleImage = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return circleImage!
}


//draw a badge view
func drawBadgeView(_ badgeString:String, badgeRadius:CGFloat = 8.5, circleFillColor:UIColor = UIColor.red, badgeFont:UIFont = UIFont.systemFont(ofSize: 11)) -> UIView {
    let badgeFrame = CGRect(x: 0, y: 0, width: badgeRadius * 2, height: badgeRadius * 2)
    
    let circleLayer = drawCircleLayer(badgeRadius, fillColor: circleFillColor)
    //let badgeView = UIView(frame: CGRectMake(0, 0, badgeRadius*2, badgeRadius*2))
    let badgeView = UIView(frame: badgeFrame)
    badgeView.layer.addSublayer(circleLayer)
    
    //let badgeLabel:UILabel = UILabel(frame: CGRectMake(0, 0, badgeRadius*2, badgeRadius*2))
    let badgeLabel:UILabel = UILabel(frame: badgeFrame)
    badgeLabel.text = badgeString
    badgeLabel.backgroundColor = UIColor.clear
    badgeLabel.textAlignment = NSTextAlignment.center
    badgeLabel.font = badgeFont
    badgeLabel.textColor = UIColor.white
    
    badgeView.addSubview(badgeLabel)
    badgeView.bringSubview(toFront: badgeLabel)
    
    return badgeView
}

//given an image, clip the round corner, return a round corner image
func drawCornerImage(_ image:UIImage, cornerRadius:CGFloat) -> UIImage {
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
    image.draw(in: tmpImageView.bounds)
    
    // Get the clipped image
    clippedCornerImage = UIGraphicsGetImageFromCurrentImageContext()!;
    
    // Lets forget about that we were drawing
    UIGraphicsEndImageContext();
    
    return clippedCornerImage
}

//draw a rectangle image, filled with color, with size
func drawRectangleImage(_ size:CGSize, color:UIColor) -> UIImage {
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
    let rectangle = CGRect(x: 0, y: 0, width: size.width, height: size.height)
    context?.addRect(rectangle)
    context?.setFillColor(color.cgColor)
    context?.fill(rectangle)
    
    // Drawing complete, retrieve the finished image and cleanup
    let image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return image!
}

//draw a rectangle image, filled with color, with size, with label
func drawRectangleImageWithLabel(_ size:CGSize, color:UIColor, label:UILabel) -> UIImage {
    let opaque:Bool = false
    let scale:CGFloat = 0
    UIGraphicsBeginImageContextWithOptions(size, opaque, scale)
    
    let context = UIGraphicsGetCurrentContext()
    //CGContextSetLineWidth(context, 4.0)
    //CGContextSetStrokeColorWithColor(context, UIColor.blueColor().CGColor)
    let rectangle = CGRect(x: 0, y: 0, width: size.width, height: size.height)
    context?.addRect(rectangle)
    context?.setFillColor(color.cgColor)
    context?.fill(rectangle)
    
    //label.drawTextInRect(rectangle)
    label.layer.render(in: context!)
    
    // Drawing complete, retrieve the finished image and cleanup
    let image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()
    
    return image!
}

//merge multiple image to single image
//Note: for round circle image, seems can not merge !
func mergeMultipleToSingleImage(_ mergedFrameSize: CGSize, imageArr:[UIImage], drawPointArr: [CGPoint]) -> UIImage {
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
        curImage.draw(at: curDrawPoint, blendMode: CGBlendMode.normal, alpha: 1.0)
    }
    
    mergedImage = UIGraphicsGetImageFromCurrentImageContext()!
    UIGraphicsEndImageContext()
    
    return mergedImage
}


extension UIImage {
    func resize(_ newSize:CGSize) -> UIImage {
        // here both true and false seems both work to resize
        //        let hasAlpha = false
        let hasAlpha = true
        let scale:CGFloat = 0.0 //system will auto get the real factor
        
        UIGraphicsBeginImageContextWithOptions(newSize, !hasAlpha, scale)
        
        self.draw(in: CGRect(origin: CGPoint.zero, size: newSize))
        
        let resizedImage:UIImage = UIGraphicsGetImageFromCurrentImageContext()!
        
        UIGraphicsEndImageContext()
        
        return resizedImage
    }
    
    func resizeToWidth(_ newWidth:CGFloat) -> UIImage {
        let scale = newWidth / self.size.width
        //print("scale=\(scale)")
        let newHeight = self.size.height * scale
        //print("newHeight=\(newHeight)")
        
        let newSize = CGSize(width: newWidth, height: newHeight)
        
        return self.resize(newSize)
    }
    
    func resizeToHeight(_ newHeight:CGFloat) -> UIImage {
        let scale = newHeight / self.size.width
        //print("scale=\(scale)")
        let newWidth = self.size.height * scale
        //print("newWidth=\(newWidth)")
        
        let newSize = CGSize(width: newWidth, height: newHeight)
        
        return self.resize(newSize)
    }
    
    func compressJpegImage(_ compressedMaxBytes: Int, compressTryStep:CGFloat = 0.01) -> Data? {
        print("self=\(self), compressedMaxBytes=\(compressedMaxBytes), compressTryStep=\(compressTryStep)")
        
        var compressedJpegData:Data? = nil
        
        let minimalCompressLevel:CGFloat = 0.01
        var curCompressQuality:CGFloat = 1.0
        
        if var jpegData = UIImageJPEGRepresentation(self, curCompressQuality) {
            //8112915 bytes
            while jpegData.count > compressedMaxBytes && curCompressQuality > minimalCompressLevel {
                curCompressQuality -= compressTryStep
                print("curCompressQuality=\(curCompressQuality)")
                
                jpegData = UIImageJPEGRepresentation(self, curCompressQuality)!
            }
            
            //309783
            compressedJpegData = jpegData
        }
        
        return compressedJpegData
    }
    
    func compressImage(_ maxImageSize:CGSize) -> UIImage {
        let originImageSize = self.size
        //self=(2448.0, 3264.0), maxSize=(360.0, 540.0) scale to newSize=(360.0, 480.0)
        let scaledSize = originImageSize.scaleToSize(AttachmentMaxImageSize)
        gLog.verbose("originImageSize=\(originImageSize) -> scaledSize=\(scaledSize)")
        //originImageSize=(3000.0, 2002.0) -> scaledSize=(360.0, 240.24)
        //originImageSize=(2448.0, 3264.0) -> scaledSize=(360.0, 480.0)
        
        let scaledImage = self.resize(scaledSize)
        gLog.verbose("scaledImage=\(scaledImage)")
        //scaledImage=<UIImage: 0x7af14e70> size {360, 240.5} orientation 0 scale 2.000000
        //scaledImage=<UIImage: 0x136725880> size {360, 480} orientation 0 scale 2.000000
        
        return scaledImage
    }
    
    func toJpegData(_ compressionQuality: CGFloat = 1.0) -> Data? {
        return UIImageJPEGRepresentation(self, compressionQuality)
    }
    
}

