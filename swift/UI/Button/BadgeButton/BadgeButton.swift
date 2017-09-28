//
//  BadgeButton.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit
import Cartography

let BadgeButtonDefaultBadgeInt:Int = 0
let BadgeButtonDefaultBadgeRadius:CGFloat = 7.0
let BadgeButtonDefaultBadgeFillColor:UIColor = UIColor.redColor()
let BadgeButtonDefaultBadgeFont:UIFont = UIFont.systemFontOfSize(10)
let BadgeButtonDefaultBadgeMoveDown:CGFloat = 0
let BadgeButtonDefaultBadgeMoveRight:CGFloat = 0

class BadgeButton: UIButton {
    
    var badgeView:UIView
    
    var badgeInt:Int {
        didSet {
            gLog.info("badgeInt=\(badgeInt)")
            
            self.updateBadgeView()
        }
    }
    
    var badgeRadius:CGFloat {
        didSet {
            gLog.info("badgeRadius=\(badgeRadius)")
            self.updateBadgeView()
        }
    }
    
    var badgeFillColor:UIColor {
        didSet {
            gLog.info("badgeFillColor=\(badgeFillColor)")
            self.updateBadgeView()
        }
    }
    
    var badgeFont:UIFont {
        didSet {
            gLog.info("badgeFont=\(badgeFont)")
            self.updateBadgeView()
        }
    }
    
    var badgeMoveDown:CGFloat {
        didSet {
            gLog.info("badgeMoveDown=\(badgeMoveDown)")
            self.updateBadgeView()
        }
    }
    
    var badgeMoveRight:CGFloat {
        didSet {
            gLog.info("badgeMoveRight=\(badgeMoveRight)")
            self.updateBadgeView()
        }
    }
    
    override init(frame: CGRect) {
        self.badgeView = UIView()
        
        self.badgeInt = BadgeButtonDefaultBadgeInt
        self.badgeRadius = BadgeButtonDefaultBadgeRadius
        self.badgeFillColor = BadgeButtonDefaultBadgeFillColor
        self.badgeFont = BadgeButtonDefaultBadgeFont
        self.badgeMoveDown = BadgeButtonDefaultBadgeMoveDown
        self.badgeMoveRight = BadgeButtonDefaultBadgeMoveRight
        
        super.init(frame: frame)
        
        self.updateBadgeView()
    }

    convenience init(badgeInt:Int, badgeRadius:CGFloat = BadgeButtonDefaultBadgeRadius, badgeFillColor:UIColor = BadgeButtonDefaultBadgeFillColor, badgeFont:UIFont = BadgeButtonDefaultBadgeFont, badgeMoveDown:CGFloat = BadgeButtonDefaultBadgeMoveDown, badgeMoveRight:CGFloat = BadgeButtonDefaultBadgeMoveRight) {
        gLog.info("badgeInt=\(badgeInt), badgeRadius=\(badgeRadius), badgeFillColor=\(badgeFillColor), badgeFont=\(badgeFont), badgeMoveDown=\(badgeMoveDown), badgeMoveRight=\(badgeMoveRight)")
        
        self.init(frame: CGRectZero)
        
        self.badgeView = UIView()
        
        self.badgeInt = badgeInt
        self.badgeRadius = badgeRadius
        self.badgeFillColor = badgeFillColor
        self.badgeFont = badgeFont
        self.badgeMoveDown = badgeMoveDown
        self.badgeMoveRight = badgeMoveRight
        
        self.updateBadgeView()
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func updateBadgeView() {
        gLog.verbose("badgeInt=\(badgeInt)")
        
        self.badgeView.removeFromSuperview()
        
        if badgeInt > 0 {
            self.badgeView.hidden = false
            self.badgeView = drawBadgeView(String(badgeInt), badgeRadius: self.badgeRadius, circleFillColor: self.badgeFillColor, badgeFont: self.badgeFont)
            
            gLog.debug("badgeView.frame=\(badgeView.frame)")
            //badgeView.frame=(0.0, 0.0, 17.0, 17.0)
            let badgeFrameSize = badgeView.frame.size
            //badgeFrameSize=(14.0, 14.0)
            self.addSubview(self.badgeView)
            constrain(self.badgeView) {badgeView in
                badgeView.top == badgeView.superview!.top - badgeFrameSize.height/2 + self.badgeMoveDown
                badgeView.right == badgeView.superview!.right - badgeFrameSize.width/2 + self.badgeMoveRight
            }
        } else {
            self.badgeView = UIView()
            self.badgeView.hidden = true
        }
    }
}

