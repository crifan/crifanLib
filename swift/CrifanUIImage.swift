//
//  CrifanUIImage.swift
//  SalesApp
//
//  Created by licrifan on 16/6/21.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import Foundation


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