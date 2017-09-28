//
//  CrifanCGSize.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

extension CGSize {
    
    func scaleToSize(_ maxSize:CGSize) -> CGSize {
        print("self=\(self), maxSize=\(maxSize)")
        
        var newSize = self
        
        let maxWidth:CGFloat = maxSize.width
        let maxHeight:CGFloat = maxSize.height
        
        let widthRatio:CGFloat = self.width / maxWidth
        let heightRatio:CGFloat = self.height / maxHeight
        print("widthRatio=\(widthRatio), heightRatio=\(heightRatio)")
        //widthRatio=8.33333, heightRatio=3.70741
        
        if (self.width >= maxWidth) && (self.height >= maxHeight) {
            if widthRatio > heightRatio {
                newSize.width = self.width / widthRatio
                newSize.height = self.height / widthRatio
            } else {
                newSize.width = self.width / heightRatio
                newSize.height = self.height / heightRatio
            }
        } else if (self.width < maxWidth) && (self.height >= maxHeight) {
            newSize.width = self.width / heightRatio
            newSize.height = self.height / heightRatio
        } else if (self.width >= maxWidth) && (self.height < maxHeight) {
            newSize.width = self.width / widthRatio
            newSize.height = self.height / widthRatio
        } else {
            newSize.width = self.width
            newSize.height = self.height
        }
        
        print("self=\(self), maxSize=\(maxSize) scale to newSize=\(newSize)")
        //self=(3000.0, 2002.0), maxSize=(360.0, 540.0) scale to newSize=(360.0, 240.24)
        
        return newSize
    }
    
}

