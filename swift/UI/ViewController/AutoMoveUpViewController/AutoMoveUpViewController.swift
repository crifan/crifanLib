//
//  AutoMoveUpViewController.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/6/19.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit
import Cartography

/*
 1. when clicked some control(eg: textfield), will show keyboard
 then will automatically move up whole view
 
 2. on the contrary, when end editing, keyboard will hide
 then will automatically mode down
 */

class AutoMoveUpViewController: UIViewController {
    var bottomView:UIView?
    
    var moveUpHeight:CGFloat
    
    var bottomToKeyboardTopPadding:CGFloat

    init(bottomView:UIView? = nil, bottomToKeyboardTopPadding:CGFloat = 10){
        gLog.verbose("bottomView=\(bottomView), bottomToKeyboardTopPadding=\(bottomToKeyboardTopPadding)")

        self.bottomView = bottomView
        self.bottomToKeyboardTopPadding = bottomToKeyboardTopPadding

        self.moveUpHeight = 0

        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    /***************************************************************************
     * View Controller Functions
     ***************************************************************************/
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        //listen keyboard to move up when keyboard show if necessary
        NSNotificationCenter.defaultCenter().addObserver(self, selector: #selector(self.keyboardWillShow(_:)), name:UIKeyboardWillShowNotification, object: nil)
        NSNotificationCenter.defaultCenter().addObserver(self, selector: #selector(self.keyboardWillHide(_:)), name:UIKeyboardWillHideNotification, object: nil)
    }

    /*************************************************************************
     * Current File Functions
     *************************************************************************/
    
    func keyboardWillShow(notification: NSNotification) {
        gLog.verbose("notification=\(notification)")

        if self.view.frame.origin.y == 0 {
            let info : NSDictionary = notification.userInfo!
            if let keyboardSize = (info[UIKeyboardFrameBeginUserInfoKey] as? NSValue)?.CGRectValue().size {
                gLog.verbose("keyboardSize=\(keyboardSize)")
                
                let keyboardHeight = keyboardSize.height
                gLog.verbose("keyboardHeight=\(keyboardHeight)")
                //keyboardHeight=216.0
                //keyboardHeight=253.0

                gLog.verbose("self.view.frame=\(self.view.frame)")
                //(0.0, 0.0, 320.0, 568.0)

                var bottomEmptyHeight:CGFloat = 0
                
                if let curBottomView = self.bottomView {
                    //has bottom view
                    
                    //calculate bottom empty height
                    gLog.verbose("curBottomView=\(curBottomView.frame)")
                    //(60.0, 215.0, 200.0, 30.0)
                    
                    guard let bottomViewSuperView = curBottomView.superview else {
                        return
                    }
                    
                    gLog.verbose("bottomViewSuperView=\(bottomViewSuperView)")
                    
                    let bottomViewFrame = bottomViewSuperView.convertRect(curBottomView.frame, toView: self.view)
                    gLog.verbose("bottomViewFrame=\(bottomViewFrame)")
                    //(60.0, 435.0, 200.0, 30.0)
                    
                    let bottomViewMaxYPos = bottomViewFrame.origin.y + bottomViewFrame.height
                    gLog.verbose("bottomViewMaxYPos=\(bottomViewMaxYPos)")
                    //465.0
                    
                    bottomEmptyHeight = self.view.frame.height - bottomViewMaxYPos
                } else {
                    //not has bottom -> consider the whole self.view's bottom as bottom position
                    bottomEmptyHeight = 0
                }
                
                gLog.verbose("keyboardHeight=\(keyboardHeight), bottomEmptyHeight=\(bottomEmptyHeight)")
                //103.0
                
                //for bottomEmptyHeight is 0 
                //-> means must not pass in bottomView
                //-> whole view to move up
                //-> must clear bottomToKeyboardTopPadding
                //-> otherwise will see black gap
                if bottomEmptyHeight == 0 {
                    bottomToKeyboardTopPadding = 0
                }
                
                if keyboardHeight > bottomEmptyHeight {
                    //calculate height to move up
                    moveUpHeight = keyboardHeight - bottomEmptyHeight + bottomToKeyboardTopPadding
                    gLog.verbose("moveUpHeight=\(moveUpHeight)")
                    //123.0
                    
                    self.view.frame.origin.y -= moveUpHeight
                    
//                    self.view.setNeedsLayout()
//                    self.view.layoutSubviews()
                }
            }
        }
    }
    
    func keyboardWillHide(notification: NSNotification) {
        gLog.verbose("notification=\(notification)")

        gLog.verbose("before hide: self.view.frame=\(self.view.frame)") //(0.0, -120.0, 320.0, 568.0)
        
        if self.view.frame.origin.y == (0 - moveUpHeight) {
            self.view.frame.origin.y += moveUpHeight
        }

        gLog.verbose("after  hide: self.view.frame=\(self.view.frame)") //(0.0, 0.0, 320.0, 568.0)
    }

}


