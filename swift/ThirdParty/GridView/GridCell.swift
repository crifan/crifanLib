//
//  GridCell.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/7/2.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

let GridCellId:String = "GridCellId"

let GridCellContentLabelFont:UIFont = UIFont.systemFontOfSize(12)
//let GridCellContentLabelTextColor:UIColor = CommonContentTextColorBlack
let GridCellContentLabelTextColor:UIColor = UIColor(hexString: "#646464")!

let GridCellBackgroundColor:UIColor = UIColor.whiteColor()


class GridCell: UICollectionViewCell {
    var contentLabel:UILabel
    
    override init(frame: CGRect) {
        self.contentLabel = UILabel()
        
        super.init(frame: frame)
        
        self.contentLabel.text = ""
        self.contentLabel.font = GridCellContentLabelFont
        self.contentLabel.textColor = GridCellContentLabelTextColor
        self.backgroundColor = GridCellBackgroundColor
        self.contentView.addSubview(self.contentLabel)

        constrain(self.contentLabel) { contentLabel in
            contentLabel.edges == contentLabel.edges
            contentLabel.center == contentLabel.superview!.center
        }
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func configCell(contentLabelFont:UIFont = UIFont.systemFontOfSize(12),
                    contentLabelTextColor:UIColor = UIColor.blackColor(),
                    cellBackgroundColor:UIColor = UIColor.whiteColor()
        ) {
        self.contentLabel.font = contentLabelFont
        self.contentLabel.textColor = contentLabelTextColor
        self.backgroundColor = cellBackgroundColor
    }
}