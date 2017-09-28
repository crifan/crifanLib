//
//  CrifanUITableViewCell.swift
//  Crifan Li
//  Updated: 2017/09/28
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
    
    //make separator left align to edge
    func setSeparatorLeftAlign() {
        self.setSeparatorLeftRightAlign(-100, rightAlign: -100)
    }
    
    func setSeparatorLeftRightAlign(_ leftAlign:CGFloat = 0, rightAlign:CGFloat = 0){
        self.separatorInset = UIEdgeInsetsMake(0, leftAlign, 0, rightAlign)
        
        //self.tableView.separatorStyle = UITableViewCellSeparatorStyle.SingleLine
        //self.separatorInset.left.add(leftAlign) //
//        self.separatorInset.left = 0//leftAlign
//        self.separatorInset.right = rightAlign
        self.layoutMargins = UIEdgeInsets.zero
        self.preservesSuperviewLayoutMargins = false
    }
    
}
