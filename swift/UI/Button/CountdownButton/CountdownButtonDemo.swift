//
//  CountdownButtonDemo.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

func CountdownButtonDemo(){    
    //let getSmsCodeButton:CountdownButton = CountdownButton(normalTitle: "发送验证码", autoStartCounddown: false)
    let getSmsCodeButton:CountdownButton = CountdownButton(normalTitle: "发送验证码")
    print("getSmsCodeButton=\(getSmsCodeButton)")
//    self.addSubview(self.getSmsCodeButton)

    //if autoStartCounddown = true, then not need this
    getSmsCodeButton.startCountdown()
    
    getSmsCodeButton.stopCountdown()
}