//
//  CountdownButton.swift
//  SalesApp
//
//  Created by licrifan on 16/6/19.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

let CountdownButtonAutoStartCounddown:Bool = true
let CountdownButtonNormalTitle:String = "发送验证码"
let CountdownButtonTotalNum:Int = 60
let CountdownButtonDisabledTitleColor:UIColor = UIColor.grayColor()
//let CountdownButtonDisabledTitleFormat:String = "发送验证码(%d秒)"
let CountdownButtonDisabledTitleFormat:String = "重新发送(%d秒)"


class CountdownButton: UIButton {
    //class CountdownButton: CommonButton {
    var autoStartCountdown:Bool
    var normalTitle:String
    var totalCountdownNum:Int
    var disabledTitleColor:UIColor
    var disabledTitleFormat:String
    
    var countdownTimer:NSTimer
    var countdownCurNum:Int
    
    override init(frame: CGRect) {
        self.autoStartCountdown = CountdownButtonAutoStartCounddown
        self.normalTitle = CountdownButtonNormalTitle
        self.totalCountdownNum = CountdownButtonTotalNum
        self.disabledTitleColor = CountdownButtonDisabledTitleColor
        self.disabledTitleFormat = CountdownButtonDisabledTitleFormat
        
        self.countdownCurNum = 0
        self.countdownTimer = NSTimer()
        
        super.init(frame: frame)
        
        if self.autoStartCountdown {
            self.addTarget(self, action: #selector(self.startCountdown), forControlEvents: UIControlEvents.TouchUpInside)
        }
        
        self.setTitle(self.normalTitle, forState:UIControlState.Normal)
    }
    
    convenience init(normalTitle:String, autoStartCounddown:Bool = CountdownButtonAutoStartCounddown, totalCountdownNum:Int = CountdownButtonTotalNum, countingDownTitleColor:UIColor = CountdownButtonDisabledTitleColor,countingDownTitleFormat:String = CountdownButtonDisabledTitleFormat) {
        self.init(frame: CGRectZero)
        
        self.autoStartCountdown = autoStartCounddown
        if !self.autoStartCountdown {
            self.removeTarget(self, action: #selector(self.startCountdown), forControlEvents: UIControlEvents.TouchUpInside)
        }
        
        self.normalTitle = normalTitle
        self.setTitle(self.normalTitle, forState:UIControlState.Normal)
        
        self.totalCountdownNum = totalCountdownNum
        
        self.disabledTitleColor = countingDownTitleColor
        self.setTitleColor(self.disabledTitleColor, forState: UIControlState.Disabled)
        
        self.disabledTitleFormat = countingDownTitleFormat
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func startCountdown() {
        gLog.debug("")
        
        self.countdownCurNum = self.totalCountdownNum
        
        updateCountdownLabel()
        
        self.countdownTimer = NSTimer.scheduledTimerWithTimeInterval(1, target: self, selector:#selector(self.updateCountdown), userInfo: nil, repeats: true)
        NSRunLoop.currentRunLoop().addTimer(self.countdownTimer, forMode: NSRunLoopCommonModes)
    }
    
    func updateCountdown() {
        gLog.debug("self.countdownCurNum=\(self.countdownCurNum)")
        self.countdownCurNum -= 1
        
        if self.countdownCurNum <= 0 {
            self.countdownTimer.invalidate()
            self.countdownCurNum  = 0
        }
        
        updateCountdownLabel()
    }
    
    func updateCountdownLabel(){
        gLog.debug("self.countdownCurNum=\(self.countdownCurNum)")
        
        dispatchMain_async({
            if self.countdownCurNum == 0 {
                let curTitle = self.normalTitle
                self.setTitle(curTitle, forState:UIControlState.Normal)
                self.setTitle(curTitle, forState:UIControlState.Disabled)
                
                self.enabled = true
            } else if self.countdownCurNum > 0 {
                let curTitle = String(format: self.disabledTitleFormat, self.countdownCurNum)
                self.setTitle(curTitle, forState:UIControlState.Disabled)
                self.setTitle(curTitle, forState:UIControlState.Normal)
                
                self.enabled = false
            }
            
            //            self.updateSmsCodeButtonUI()
        })
    }
    
    func stopCountdown(){
        gLog.debug("stopCountdown: self.countdownCurNum=\(self.countdownCurNum)")
        
        self.countdownTimer.invalidate()
        
        self.countdownCurNum = 0
        
        updateCountdownLabel()
        
    }
    
    //    func updateSmsCodeButtonUI(){
    //        if self.enabled {
    //            self.backgroundColor = UIColor.whiteColor()
    //            self.layer.borderColor = ColorButtonBackgroud.CGColor
    //            self.setTitleColor(ColorButtonBackgroud, forState: UIControlState.Normal)
    //        } else {
    //            self.backgroundColor = UIColor.clearColor()
    //            self.layer.borderColor = ColorTextFieldBorderGray.CGColor
    //            self.setTitleColor(ColorTextFieldPlaceholderGray, forState: UIControlState.Disabled)
    //        }
    //    }
}

