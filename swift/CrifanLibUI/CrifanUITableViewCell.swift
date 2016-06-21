//
//  CrifanUITableViewCell.swift
//  SalesApp
//
//  Created by licrifan on 16/6/21.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

/***************************************************************************
 * Table View functions
 ***************************************************************************/

extension UITableViewCell {
    func hideSeparator() {
        let indentLargeEnoughToHide:CGFloat = 10000
        // indent large engough for separator(including cell' content) to hidden separator
        self.separatorInset = UIEdgeInsetsMake(0, indentLargeEnoughToHide, 0, 0)
        // adjust the cell's content to show normally
        self.indentationWidth = indentLargeEnoughToHide * -1
        // must add this, otherwise default is 0, now actual indentation = indentationWidth * indentationLevel = 10000 * 1 = -10000
        self.indentationLevel = 1
    }

/*
    func setTableViewCellSeparatorLeftInset0(tableViewCell:UITableViewCell) {
        //make separator left align to edge
        tableViewCell.separatorInset = UIEdgeInsetsZero
        tableViewCell.layoutMargins = UIEdgeInsetsZero
        //tableViewCell.layoutMargins.left = 0
        tableViewCell.preservesSuperviewLayoutMargins = false
    }
 
    func setTableViewCellSeparatorBothInset(tableViewCell:UITableViewCell){
        let AllPageLeftRightPadding:CGFloat = 15.0
        
        tableViewCell.separatorInset = UIEdgeInsetsMake(0, AllPageLeftRightPadding, 0, AllPageLeftRightPadding)
        tableViewCell.layoutMargins = UIEdgeInsetsZero
        // tableViewCell.preservesSuperviewLayoutMargins = false
    }
*/
    
    //make separator left align to edge
    func setSeparatorLeftAlign() {
        self.setSeparatorLeftRightAlign(0)

        self.preservesSuperviewLayoutMargins = false
    }
    
    func setSeparatorLeftRightAlign(leftAlign:CGFloat = 0, rightAlign:CGFloat = 0){
        self.separatorInset = UIEdgeInsetsMake(0, leftAlign, 0, rightAlign)
        self.layoutMargins = UIEdgeInsetsZero
        // tableViewCell.preservesSuperviewLayoutMargins = false
    }

}
