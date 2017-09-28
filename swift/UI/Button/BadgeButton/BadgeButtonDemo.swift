//
//  BadgeButtonDemo.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

func BadgeButtonDemo(){
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
}