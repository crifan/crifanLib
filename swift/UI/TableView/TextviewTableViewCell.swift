//
//  TextviewTableViewCell.swift
//  Xxx
//
//  Created by licrifan on 16/6/10.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography
import KMPlaceholderTextView

let TextviewTableViewCellId:String = "TextviewTableViewCellId"
let TextviewTVCHeight:CGFloat = 44


class TextviewTableViewCell: UITableViewCell {
    var textview:KMPlaceholderTextView
    var editable:Bool
    
    init(editable:Bool = false,
         reuseIdentifier: String? = nil,
         rightTextviewText:String = "",
         rightTextviewFont:UIFont = RightTextFieldTextFont,
         rightTextviewColor:UIColor = RightTextFieldTextColor,
         rightTextviewPlaceholder:String = ""
        ) {
        self.editable = editable
        
        self.textview = KMPlaceholderTextView()
        self.textview.text = rightTextviewText
        self.textview.placeholder = rightTextviewPlaceholder
        
        super.init(style: .Default, reuseIdentifier: reuseIdentifier ?? TextviewTableViewCellId)

        self.contentView.backgroundColor = UIColor.whiteColor()
        
        self.textview.editable = self.editable
        self.textview.font = rightTextviewFont
        self.textview.textColor = rightTextviewColor
        self.contentView.addSubview(self.textview)
        
        constrain(self.textview){ textview in
//            textview.left    == textview.superview!.left + AllPagePaddingX
            textview.top == textview.superview!.top
            textview.bottom == textview.superview!.bottom
            textview.left    == textview.superview!.left
            textview.right   == textview.superview!.right
            //textview.centerY == textview.superview!.centerY
            textview.height == TextviewTVCHeight
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}
