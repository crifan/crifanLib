//
//  TapToHideViewController.swift
//  SalesApp
//
//  Created by licrifan on 16/6/19.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

/*
 click/tap the view out side of notHideView
 -> will dissmiss current view controller
 -> and call the hideVCHandler if not nil
*/

class TapToHideViewController: UIViewController, UIGestureRecognizerDelegate {
    var notHideView:UIView

    var hideVCHandler: ((Void) -> Void)?

    var tapToHideRecog:UITapGestureRecognizer!

    init(notHideView:UIView, hideVCHandler:((Void) -> Void)? = nil) {
        gLog.verbose("notHideView=\(notHideView)")
        
        self.notHideView = notHideView
        self.hideVCHandler = hideVCHandler

        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.tapToHideRecog = UITapGestureRecognizer(target: self, action: #selector(self.dismissCurVC(_:)))
        self.tapToHideRecog.numberOfTapsRequired = 1
        self.tapToHideRecog.delegate = self
        //self.tapToHideRecog.cancelsTouchesInView = false
        self.view.addGestureRecognizer(self.tapToHideRecog)
    }
    
    /*************************************************************************
     * Current File Functions
     *************************************************************************/
    
    /***************************************************************************
     * UIGestureRecognizerDelegate functions
     ***************************************************************************/
    
    func gestureRecognizer(gestureRecognizer: UIGestureRecognizer, shouldReceiveTouch touch: UITouch) -> Bool {
        gLog.debug("touch=\(touch), touch.view=\(touch.view)")
        
        //get touch/tap point/position in current view
        let touchPoint = touch.locationInView(self.view)
        gLog.debug("touchPoint=\(touchPoint)")
        
        //check tap point in subview or not
        if CGRectContainsPoint(self.notHideView.frame, touchPoint){
            gLog.verbose("clicked within notHideView=\(notHideView) -> should not hide")

            return false
        } else {
            gLog.verbose("clicked out of notHideView=\(notHideView) -> need hide")

            return true
        }
    }
    
    func dismissCurVC(tapRecog:UITapGestureRecognizer){
        gLog.verbose("tapRecog=\(tapRecog)")
        
        gLog.verbose("hideVCHandler=\(hideVCHandler)")

        if self.hideVCHandler != nil {
            self.hideVCHandler!()
        }

        dispatchMain_async({
            self.dismissViewControllerAnimated(true, completion: nil)
        })
    }
}
