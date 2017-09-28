//
//  CrifanUILabel.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

/***************************************************************************
 * UITextView/UILabel Related functions
 ***************************************************************************/

//calc real text size for UITextView text
func calcTexViewTextSize(text:String, font:UIFont, widthLimit:CGFloat)
    -> CGSize {
        let tmpTextView = UITextView(frame: CGRectZero)
        tmpTextView.font = font
        tmpTextView.text = text
        //Terminating app due to uncaught exception 'NSInternalInconsistencyException', reason: 'Only run on the main thread!'
        let realTextSize = tmpTextView.sizeThatFits(CGSize(width: widthLimit, height: CGFloat.max))
        //print("calculated realTextSize=\(realTextSize)")
        
        return realTextSize
}

//caculate text size for UILabel text
func calcLabelTextSize(_ text:String, font:UIFont) -> CGSize {
    let textLabel:UILabel = UILabel()
    textLabel.text = text
    textLabel.font = font
    textLabel.sizeToFit()
    let labelTextSize:CGSize = textLabel.bounds.size
    
    return labelTextSize
}

//caculate text size for UILabel text
func calcLabelTextSizeWithWidthLimit(_ text:String, font:UIFont, widthLimit:CGFloat) -> CGSize {
    let textLabel:UILabel = UILabel(frame: CGRect(
        x: 0,
        y: 0,
        width: widthLimit,
        height: CGFloat.greatestFiniteMagnitude))
    textLabel.text = text
    textLabel.font = font
    textLabel.numberOfLines = 0
    //print("textLabel.frame=\(textLabel.frame)")
    textLabel.sizeToFit()
    //print("textLabel.frame=\(textLabel.frame)")
    
    let labelTextSize:CGSize = textLabel.bounds.size
    
    return labelTextSize
}
