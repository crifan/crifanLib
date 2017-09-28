//
//  CountdownButton.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

let CountdownButtonAutoStartCountdown:Bool = true
let CountdownButtonNormalTitle:String = "发送验证码"
let CountdownButtonTotalNum:Int = 60
let CountdownButtonDisabledTitleColor:UIColor = UIColor.gray
//let CountdownButtonDisabledTitleFormat:String = "发送验证码(%d秒)"
let CountdownButtonDisabledTitleFormat:String = "(%d s)"//"重新发送(%d秒)"


class CountdownButton: CommonButton {
    //class CountdownButton: UIButton {
    var autoStartCountdown:Bool
    var normalTitle:String
    var totalCountdownNum:Int
    var disabledTitleFormat:String
    
    var countdownTimer:Timer
    var countdownCurNum:Int
    
    override init(frame: CGRect) {
        self.autoStartCountdown = CountdownButtonAutoStartCountdown
        self.normalTitle = CountdownButtonNormalTitle
        self.totalCountdownNum = CountdownButtonTotalNum
        self.disabledTitleFormat = CountdownButtonDisabledTitleFormat
        
        self.countdownCurNum = 0
        self.countdownTimer = Timer()
        
        super.init(frame: frame)
        
        if self.autoStartCountdown {
            self.addTarget(self, action: #selector(self.startCountdown), for: UIControlEvents.touchUpInside)
        }
        
        self.setTitle(self.normalTitle, for:UIControlState())
    }
    
    convenience init(normalTitle:String,
                     autoStartCountdown:Bool = CountdownButtonAutoStartCountdown,
                     totalCountdownNum:Int = CountdownButtonTotalNum,
                     countingDownTitleFormat:String = CountdownButtonDisabledTitleFormat) {
        self.init(frame: CGRect.zero)
        
        self.autoStartCountdown = autoStartCountdown
        if !self.autoStartCountdown {
            self.removeTarget(self, action: #selector(self.startCountdown), for: UIControlEvents.touchUpInside)
        }
        
        self.normalTitle = normalTitle
        self.setTitle(self.normalTitle, for:UIControlState())
        
        self.totalCountdownNum = totalCountdownNum
        
        self.disabledTitleFormat = countingDownTitleFormat
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func startCountdown() {
        gLog.debug("")
        
        self.countdownCurNum = self.totalCountdownNum
        
        updateCountdownLabel()
        
        self.countdownTimer = Timer.scheduledTimer(timeInterval: 1, target: self, selector:#selector(self.updateCountdown), userInfo: nil, repeats: true)
        RunLoop.current.add(self.countdownTimer, forMode: RunLoopMode.commonModes)
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
                self.isEnabled = true
                
                let curTitle = self.normalTitle
                self.setTitle(curTitle, for:UIControlState())
                self.setTitle(curTitle, for:UIControlState.disabled)
            } else if self.countdownCurNum > 0 {
                self.isEnabled = false
                
                let curTitle = String(format: self.disabledTitleFormat, self.countdownCurNum)
                self.setTitle(curTitle, for:UIControlState.disabled)
                self.setTitle(curTitle, for:UIControlState())
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

}
