//
//  LeftLabelRightSegmentedControlTableViewCell.swift
//  Xxx
//
//  Created by licrifan on 16/6/10.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

let LeftLabelRightSegmentedControlTableViewCellId:String = "LeftLabelRightSegmentedControlTableViewCellId"

//let LeftLabelRightSegmentedControlSegmentedControlColor:UIColor   = UIColor(hexString: "#DC1B7F")!

//let RightSegmentedFont:UIFont = UIFont.systemFontOfSize(9)
let RightSegmentedFont:UIFont = UIFont.systemFontOfSize(11)

class LeftLabelRightSegmentedControlTableViewCell: LeftLabelRightTextfieldTableViewCell {
    var segmentedControl :UISegmentedControl

    init(editable:Bool = false,
         reuseIdentifier: String? = nil,
         leftLabelText:String = "",
         isMandatory:Bool = false,
         optionList:[String] = [String](),
         curSelectedIdx:Int = 0,
         segmentedFont:UIFont = RightSegmentedFont
        ) {
        self.segmentedControl = UISegmentedControl()

        if editable {
            super.init(editable: editable, reuseIdentifier: reuseIdentifier ?? LeftLabelRightSegmentedControlTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory, rightTextFieldText: "")
            
            self.segmentedControl = UISegmentedControl(items: optionList)
            self.segmentedControl.selectedSegmentIndex = curSelectedIdx
            //self.segmentedControl.tintColor = LeftLabelRightSegmentedControlSegmentedControlColor
            self.segmentedControl.tintColor = CommonButtonColor
            self.segmentedControl.setTitleTextAttributes([NSFontAttributeName: segmentedFont], forState: .Normal)
            self.contentView.addSubview(segmentedControl)
            
            constrain(segmentedControl){segmentedControl in
                segmentedControl.left    == segmentedControl.superview!.left + RightTextfiledPaddingLeftToParent
                segmentedControl.right   == segmentedControl.superview!.right - AllPagePaddingX
                segmentedControl.centerY == segmentedControl.superview!.centerY
                //segmentedControl.height  == 30
                segmentedControl.height  == segmentedControl.superview!.height * 0.8
            }
        } else {
            var rightTextFieldText = ""

            if (curSelectedIdx >= 0) && (curSelectedIdx < optionList.count) {
                rightTextFieldText = optionList[curSelectedIdx]
            }
            
            super.init(editable: editable, reuseIdentifier: reuseIdentifier ?? LeftLabelRightSegmentedControlTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory, rightTextFieldText: rightTextFieldText)
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}
