//
//  CrifanLibUIDemo.swift
//  SalesApp
//
//  Created by licrifan on 16/6/8.
//  Copyright © 2016年 licrifan. All rights reserved.
//
//  Last Update: 2016-06-08

import UIKit

//unuseful function CrifanLibUIDemo, just for demo usage for CrifanLibUI
func CrifanLibUIDemo(){

    /***************************************************************************
     * BadgeButton demo
     ***************************************************************************/
    
    let messageBadgeButton = BadgeButton()
    
    //top right messages
    messageBadgeButton.frame = CGRectMake(0, 0, NaviMessageImage.size.width, NaviMessageImage.size.height)
    messageBadgeButton.setImage(NaviMessageImage, forState: UIControlState.Normal)
    //messageBadgeButton.addTarget(self, action: #selector(self.showMessageVC), forControlEvents: UIControlEvents.TouchUpInside)
    messageBadgeButton.badgeMoveDown = 3
    messageBadgeButton.badgeMoveRight = 0
    
    let messageBarItem = UIBarButtonItem(customView: messageBadgeButton)
    
    SingletonMainVC().navigationItem.setRightBarButtonItem(messageBarItem, animated: false)
    
    //will auto update badge view
    messageBadgeButton.badgeInt = 4
    
    /***************************************************************************
     * CountdownButton demo
     ***************************************************************************/

    //let getSmsCodeButton:CountdownButton = CountdownButton(normalTitle: "发送验证码", autoStartCounddown: false)
    let getSmsCodeButton:CountdownButton = CountdownButton(normalTitle: "发送验证码")
    print("getSmsCodeButton=\(getSmsCodeButton)")
//    self.addSubview(self.getSmsCodeButton)

    //if autoStartCounddown = true, then not need this
    getSmsCodeButton.startCountdown()
    
    getSmsCodeButton.stopCountdown()

}