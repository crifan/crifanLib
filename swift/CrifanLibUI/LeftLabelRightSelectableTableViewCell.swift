//
//  LeftLabelRightSelectableTableViewCell.swift
//  SalesApp
//
//  Created by licrifan on 16/6/10.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

let LeftLabelRightSelectableTableViewCellId:String = "LeftLabelRightSelectableTableViewCellId"

class LeftLabelRightSelectableTableViewCell: LeftLabelRightTextfieldTableViewCell {
    var selectable:Bool
    var itemList:[String]

    init(selectable:Bool = false,
         reuseIdentifier: String? = nil,
         leftLabelText:String = "",
         isMandatory:Bool = false,
         rightTextFieldText:String = "",
         rightTextFieldTextColor:UIColor = RightTextFieldTextColor,
         rightTextFieldTextFont:UIFont = RightTextFieldTextFont,
         itemList:[String] = [String]()
        ) {
        self.selectable = selectable
        self.itemList = itemList

//        super.init(editable: editable, reuseIdentifier: reuseIdentifier ?? LeftLabelRightSelectableTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory, rightTextFieldText: rightTextFieldText)
        super.init(editable: false, reuseIdentifier: reuseIdentifier ?? LeftLabelRightSelectableTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory, rightTextFieldText: rightTextFieldText, rightTextFieldTextColor: rightTextFieldTextColor, rightTextFieldTextFont: rightTextFieldTextFont)
        
        if self.selectable {
            self.accessoryType = .DisclosureIndicator
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}
