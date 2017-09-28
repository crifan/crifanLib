//
//  LeftLabelRightTextfieldTableViewCell.swift
//  SalesApp
//
//  Created by licrifan on 16/6/10.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

let LeftLabelRightTextfieldTableViewCellId:String = "LeftLabelRightTextfieldTableViewCellId"


let RightTextFieldTextColor:UIColor = CommonTextColorBlack
let RightTextFieldTextFont:UIFont   = UIFont.systemFontOfSize(15)
//let CustomerDetailRightTextfiledPaddingLeftToParent:CGFloat = 90
//let RightTextfiledPaddingLeftToParent:CGFloat = 90
let RightTextfiledPaddingLeftToParent:CGFloat = 98

class LeftLabelRightTextfieldTableViewCell: LeftLabelTableViewCell {
    var rightTextfield:UITextField
    var editable: Bool
    
    init(editable:Bool = false,
         reuseIdentifier: String? = nil,
         leftLabelText:String = "",
         isMandatory:Bool = false,
         rightTextFieldText:String = "",
         rightTextFieldPlaceholder:String = "",
         rightTextFieldTextColor:UIColor = RightTextFieldTextColor,
         rightTextFieldTextFont:UIFont = RightTextFieldTextFont,
         constrainToParentRight:CGFloat = AllPagePaddingX
        ) {
        self.editable = editable
        
        self.rightTextfield = UITextField()
        self.rightTextfield.text = rightTextFieldText
        self.rightTextfield.placeholder = rightTextFieldPlaceholder
        
        super.init(leftLabelText: leftLabelText, reuseIdentifier: reuseIdentifier ?? LeftLabelRightTextfieldTableViewCellId, isMandatory: isMandatory)
        
        if editable {
            self.rightTextfield.userInteractionEnabled = true
            self.rightTextfield.enabled = true
        } else {
//            self.rightTextfield.userInteractionEnabled = false
            self.rightTextfield.enabled = false
        }
        
        self.contentView.addSubview(self.rightTextfield)
        self.rightTextfield.textAlignment = .Left
        self.rightTextfield.font = rightTextFieldTextFont
        self.rightTextfield.textColor = rightTextFieldTextColor
//        constrain(self.rightTextfield, self.leftLabel, self.mandatoryImageview){rightTextfield, leftLabel, mandatoryImageview in
        constrain(self.rightTextfield){rightTextfield in
            rightTextfield.left    == rightTextfield.superview!.left + RightTextfiledPaddingLeftToParent
//            if self.isMandatory {
//                rightTextfield.left     >= mandatoryImageview.right
//            } else {
//                rightTextfield.left     >= leftLabel.right
//            }

            rightTextfield.right   == rightTextfield.superview!.right - constrainToParentRight
            rightTextfield.centerY == rightTextfield.superview!.centerY
        }
  
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    
}
