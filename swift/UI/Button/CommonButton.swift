//
//  CommonButton.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit
import Cartography

//let CommonButtonColor:UIColor = UIColor(hexString: "#CC0486")!
let CommonButtonColor:UIColor = AppMainColor//UIColor(hexString: "#3D90C9")!


let CommonButtonDisabledColor:UIColor = UIColor.gray

let CommonButtonTitleFont:UIFont = UIFont.systemFont(ofSize: 15)

let CommonButtonHeight:CGFloat = 30

class CommonButton: UIButton {
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        
        self.layer.borderColor = CommonButtonColor.cgColor
        self.layer.borderWidth = 1
        self.layer.cornerRadius = 5
        
        self.backgroundColor = UIColor.clear
        self.setTitleColor(CommonButtonColor, for: UIControlState())
        self.setTitleColor(CommonButtonDisabledColor, for: UIControlState.disabled)
        
        self.titleLabel?.font = CommonButtonTitleFont
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override var isEnabled: Bool{
        didSet {
            if isEnabled {
                self.layer.borderColor = CommonButtonColor.cgColor
            } else {
                self.layer.borderColor = CommonButtonDisabledColor.cgColor
            }
        }
    }
}

