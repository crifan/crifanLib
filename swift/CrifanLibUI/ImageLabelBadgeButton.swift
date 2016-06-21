//
//  ImageLabelBadgeButton.swift
//  SalesApp
//
//  Created by licrifan on 16/6/17.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

enum ImageLabelPositionMode:Int {
    case ImageLeftLabelRight
    case ImageRightLabelLeft
    case ImageTopLabelBottom
    case ImageBottomLabelTop
}

class ImageLabelBadgeButton: BadgeButton {
    var curImageView:UIImageView
    var curTitleLabel:UILabel
    
    init(curImage:UIImage,
         curTitle:String,
         positionMode:ImageLabelPositionMode = .ImageLeftLabelRight,
         titleFont:UIFont = RightTextFieldTextFont,
         titleColor:UIColor = RightTextFieldTextColor,
         titleAlignment:NSTextAlignment = .Left,
         titleHeight:CGFloat = 0,
         paddingLeft:CGFloat = 0,
         paddingTop:CGFloat = 0,
         paddingRight:CGFloat = 0,
         paddingBottom:CGFloat = 0,
         paddingHorizontal:CGFloat = 0,
         paddingVertical:CGFloat = 0
         ) {
        gLog.debug("curImage=\(curImage), newTitle=\(curTitle), positionMode=\(positionMode), titleFont=\(titleFont), titleColor=\(titleColor), titleAlignment=\(titleAlignment), titleHeight=\(titleHeight), paddingLeft=\(paddingLeft), paddingTop=\(paddingTop), paddingRight=\(paddingRight), paddingBottom=\(paddingBottom), paddingHorizontal=\(paddingHorizontal), paddingVertical=\(paddingVertical)")
        
        self.curImageView = UIImageView()
        self.curTitleLabel = UILabel()
        
        super.init(frame: CGRectZero)
        
        let curImageSize = curImage.size
        gLog.debug("curImageSize=\(curImageSize)")

        //1. image view
        self.addSubview(self.curImageView)
        self.curImageView.image = curImage

        //2. title label
        self.addSubview(self.curTitleLabel)
        self.curTitleLabel.text = curTitle
        self.curTitleLabel.textAlignment = titleAlignment
        self.curTitleLabel.font = titleFont
        self.curTitleLabel.textColor = titleColor

        if positionMode == .ImageLeftLabelRight {
            constrain(self.curImageView) {curImageView in
                curImageView.left == curImageView.superview!.left + paddingLeft
                curImageView.width == curImageSize.width
                curImageView.centerY == curImageView.superview!.centerY
            }
            
            constrain(curTitleLabel, curImageView) {curTitleLabel, curImageView in
                curTitleLabel.left == curImageView.right + paddingHorizontal
                curTitleLabel.centerY == curTitleLabel.superview!.centerY
                curTitleLabel.width <= curTitleLabel.superview!.width
            }
        } else if positionMode == .ImageTopLabelBottom {
            constrain(self.curImageView) {curImageView in
                curImageView.top == curImageView.superview!.top + paddingTop
                curImageView.height == curImageSize.height
                curImageView.width == curImageSize.width
                curImageView.centerX == curImageView.superview!.centerX
            }

            constrain(curTitleLabel, curImageView) {curTitleLabel, curImageView in
                curTitleLabel.top == curImageView.bottom + paddingVertical
                if titleHeight != 0 {
                    curTitleLabel.height == titleHeight
                }
                curTitleLabel.width <= curTitleLabel.superview!.width
                curTitleLabel.centerX == curTitleLabel.superview!.centerX
            }
        }

    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}