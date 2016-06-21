//
//  LeftLabelRightTextviewTableViewCell.swift
//  SalesApp
//
//  Created by licrifan on 16/6/18.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography
import KMPlaceholderTextView

let LeftLabelRightTextviewTableViewCellId:String = "LeftLabelRightTextviewTableViewCellId"

let RightTextviewHeight:CGFloat = 60

class LeftLabelRightTextviewTableViewCell: LeftLabelTableViewCell {
    var rightTextview:KMPlaceholderTextView
    var editable: Bool
    
    init(editable:Bool = false,
         reuseIdentifier: String? = nil,
         leftLabelText:String = "",
         isMandatory:Bool = false,
         rightTextviewText:String = "",
         rightTextviewPlaceholder:String = "",
         rightTextviewTextColor:UIColor = RightTextFieldTextColor,
         rightTextviewTextFont:UIFont = RightTextFieldTextFont
        ) {
        self.editable = editable
        self.rightTextview = KMPlaceholderTextView()

        super.init(leftLabelText: leftLabelText, reuseIdentifier: reuseIdentifier ?? LeftLabelRightTextviewTableViewCellId, isMandatory: isMandatory)
        
        self.rightTextview.text = rightTextviewText
        self.rightTextview.placeholder = rightTextviewPlaceholder

        if !self.editable {
            self.rightTextview.editable = false
        }
        
        self.contentView.addSubview(self.rightTextview)
        constrain(self.rightTextview) {rightTextview in
            rightTextview.left == rightTextview.superview!.left + RightTextfiledPaddingLeftToParent
            rightTextview.right <= rightTextview.superview!.right
            rightTextview.height == RightTextviewHeight
            rightTextview.bottom == rightTextview.superview!.bottom
        }
        
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

