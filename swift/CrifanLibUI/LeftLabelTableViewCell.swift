//
//  LeftLabelTableViewCell.swift
//  SalesApp
//
//  Created by licrifan on 16/6/8.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

let LeftLabelTableViewCellId:String = "LeftLabelTableViewCellId"

let LeftLabelTVCLabelColor:UIColor = UIColor(hexString: "#999999")!
let LeftLabelTVCLabelFont:UIFont = UIFont.systemFontOfSize(15)
let LeftLabelTVCMaxWidth:CGFloat = 70

let LeftLabelTVCBackgroundColor:UIColor = UIColor.whiteColor()

class LeftLabelTableViewCell: UITableViewCell {
    var leftLabel:UILabel
    var mandatoryImageview:UIImageView
    var isMandatory:Bool

    init(leftLabelText:String,
         reuseIdentifier:String? = nil,
         leftLabelColor:UIColor = LeftLabelTVCLabelColor,
         leftLabelFont:UIFont = LeftLabelTVCLabelFont,
         isMandatory:Bool = false,
         leftLabelMaxWidth:CGFloat = LeftLabelTVCMaxWidth
        ){
        self.leftLabel = UILabel()
        self.mandatoryImageview = UIImageView()
        self.isMandatory = isMandatory
        
        super.init(style: UITableViewCellStyle.Default, reuseIdentifier: reuseIdentifier)
        self.selectionStyle = UITableViewCellSelectionStyle.None
        
        self.imageView?.image = nil
        self.imageView?.hidden = true
        self.textLabel?.text = nil
        self.textLabel?.hidden = true
        
        self.accessoryType = UITableViewCellAccessoryType.None
        self.accessoryView = nil
        
        self.backgroundColor = LeftLabelTVCBackgroundColor
        
        
        self.isMandatory = isMandatory
        
        self.leftLabel.numberOfLines = 0

        self.leftLabel.text = leftLabelText
        self.leftLabel.textColor = leftLabelColor
        self.leftLabel.font = leftLabelFont
        self.contentView.addSubview(self.leftLabel)
        constrain(self.leftLabel){ leftLabel in
            leftLabel.left    == leftLabel.superview!.left + AllPagePaddingX
            //leftLabel.width   <= LeftLabelTVCMaxWidth
            leftLabel.width   <= leftLabelMaxWidth
            leftLabel.centerY == leftLabel.superview!.centerY
            
            //leftLabel.right <= leftLabel.superview!.right + RightTextfiledPaddingLeftToParent
        }
        
        if self.isMandatory {
            self.mandatoryImageview.hidden = false
            
            let mandatoryImage:UIImage  = UIImage(named: "important_star")!
            self.mandatoryImageview.image  = mandatoryImage
            self.contentView.addSubview(self.mandatoryImageview)
            constrain(self.mandatoryImageview, self.leftLabel){ mandatoryImageview, leftLabel in
                mandatoryImageview.left    == leftLabel.right + 5
                mandatoryImageview.centerY == leftLabel.centerY
                mandatoryImageview.width   == mandatoryImage.size.width
                mandatoryImageview.height  == mandatoryImage.size.height
                
                //mandatoryImageview.right <= mandatoryImageview.superview!.right + RightTextfiledPaddingLeftToParent
            }
        } else {
            self.mandatoryImageview.hidden = true
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

}