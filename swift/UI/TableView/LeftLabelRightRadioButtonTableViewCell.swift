//
//  LeftLabelRightRadioButtonTableViewCell.swift
//  Xxx
//
//  Created by licrifan on 16/6/10.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography
import DLRadioButton

let LeftLabelRightRadioButtonTableViewCellId:String = "LeftLabelRightRadioButtonTableViewCellId"

let SingleRadioButtonWidth:CGFloat = 60

let RadioButtonUnselectedImage = UIImage(named: "radio_button_unselected")!
let RadioButtonSelectedImage = UIImage(named: "radio_button_selected")!


class LeftLabelRightRadioButtonTableViewCell: LeftLabelRightTextfieldTableViewCell {
    var optionList:[String]

    init(editable:Bool = false,
         reuseIdentifier: String? = nil,
         leftLabelText:String = "",
         isMandatory:Bool = false,
         optionList:[String] = [String](),
         curSelectedIdx:Int = 0,
         buttonSelectedTarget:UIViewController? = nil,
         buttonSelectedHandler:Selector = nil
        ) {

        self.optionList = optionList
        
        if editable {
            super.init(editable: false, reuseIdentifier: reuseIdentifier ?? LeftLabelRightRadioButtonTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory)
            
            self.rightTextfield.hidden = true
            
            let firstRadioButton = DLRadioButton()
            radioButtonCommonSetup(firstRadioButton, buttonSelectedTarget: buttonSelectedTarget, buttonSelectedHandler: buttonSelectedHandler)
            firstRadioButton.tag = 0
            firstRadioButton.setTitle(self.optionList[0], forState: UIControlState.Normal)
            self.contentView.addSubview(firstRadioButton)

            if (curSelectedIdx >= 0) && (curSelectedIdx < self.optionList.count) {
                if firstRadioButton.tag == curSelectedIdx {
                    firstRadioButton.selected = true
                }
            }
            
//            //for debug
//            firstRadioButton.backgroundColor = UIColor.greenColor()

            constrain(firstRadioButton) {firstRadioButton in
                firstRadioButton.left == firstRadioButton.superview!.left + RightTextfiledPaddingLeftToParent
                firstRadioButton.centerY == firstRadioButton.superview!.centerY
                firstRadioButton.width == SingleRadioButtonWidth
            }

            var otherButtonList = [DLRadioButton]()
            
            for curIdx in 1..<self.optionList.count {
                let curSelection = self.optionList[curIdx]
                gLog.verbose("[\(curIdx)] curSelection=\(curSelection)")

                let curRadioButton = DLRadioButton()
                curRadioButton.tag = curIdx
                radioButtonCommonSetup(curRadioButton, buttonSelectedTarget: buttonSelectedTarget, buttonSelectedHandler: buttonSelectedHandler)
                curRadioButton.setTitle(curSelection, forState: UIControlState.Normal)
                self.contentView.addSubview(curRadioButton)
                
                let currentButtonPaddingLeft:CGFloat = RightTextfiledPaddingLeftToParent + (CGFloat(curIdx)*SingleRadioButtonWidth)
                gLog.verbose("currentButtonPaddingLeft=\(currentButtonPaddingLeft)")

                constrain(curRadioButton) {curRadioButton in
                    curRadioButton.left == curRadioButton.superview!.left + currentButtonPaddingLeft
                    curRadioButton.centerY == curRadioButton.superview!.centerY
                    curRadioButton.width == SingleRadioButtonWidth
                }
                
                if (curSelectedIdx >= 0) && (curSelectedIdx < self.optionList.count) {
                    if curRadioButton.tag == curSelectedIdx {
                        curRadioButton.selected = true
                    }
                }
                
                otherButtonList.append(curRadioButton)
     
            }

            firstRadioButton.otherButtons = otherButtonList
            
            
        } else {
            var rightTextFieldText = ""

            if self.optionList.count > 0 {
                if curSelectedIdx < 0 {
                    rightTextFieldText = self.optionList[0]
                } else {
                    if curSelectedIdx < self.optionList.count {
                        rightTextFieldText = self.optionList[curSelectedIdx]
                    }
                }
            }
            
            super.init(editable: editable, reuseIdentifier: reuseIdentifier ?? LeftLabelRightRadioButtonTableViewCellId, leftLabelText: leftLabelText, isMandatory: isMandatory, rightTextFieldText: rightTextFieldText)
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    
    func radioButtonCommonSetup(radioButton:DLRadioButton, buttonSelectedTarget:UIViewController?, buttonSelectedHandler:Selector) {
        gLog.verbose("radioButton=\(radioButton), buttonSelectedTarget=\(buttonSelectedTarget), buttonSelectedHandler=\(buttonSelectedHandler)")
        //radioButton=<DLRadioButton: 0x79eccf90; baseClass = UIButton; frame = (0 0; 0 0); opaque = NO; layer = <CALayer: 0x79ebddd0>>, buttonSelectedTarget=Optional(<Xxx.CustomerDetailViewController: 0x79ecd940>), buttonSelectedHandler=radioButtonSelected:
        
//        radioButton.titleLabel?.textAlignment = .Left
        radioButton.titleLabel!.font = RightTextFieldTextFont
        radioButton.setTitleColor(RightTextFieldTextColor, forState: UIControlState.Normal)
        radioButton.icon = RadioButtonUnselectedImage
        radioButton.iconSelected = RadioButtonSelectedImage
        radioButton.marginWidth = 0
        radioButton.iconStrokeWidth = 2
//        radioButton.iconSize = RadioButtonUnselectedImage.size.width
        radioButton.indicatorSize = 1
        radioButton.contentHorizontalAlignment = UIControlContentHorizontalAlignment.Left
//        radioButton.addTarget(self, action: #selector(self.radioButtonSelected(_:)), forControlEvents: UIControlEvents.TouchUpInside)

        if (buttonSelectedTarget != nil ) && (buttonSelectedHandler != nil) {
//            radioButton.addTarget(self, action: buttonSelectedHandler, forControlEvents: UIControlEvents.TouchUpInside)
            radioButton.addTarget(buttonSelectedTarget, action: buttonSelectedHandler, forControlEvents: UIControlEvents.TouchUpInside)
        }
    }

//    func radioButtonSelected(radioButton: DLRadioButton) {
//        gLog.verbose("radioButton=\(radioButton), text=\(radioButton.titleLabel!.text), tag=\(radioButton.tag)")
//
//        if (radioButton.multipleSelectionEnabled) {
//            for button in radioButton.selectedButtons() {
//                gLog.verbose(String(format: "%@ is selected", button.titleLabel!.text!));
//            }
//        } else {
//            gLog.verbose(String(format: "%@ is selected", radioButton.selectedButton()!.titleLabel!.text!));
//        }
//    }
}
