//
//  CrifanDevice.swift
//  Crifan Li
//  Updated: 2017/11/09
//

import UIKit

extension UIDevice {
    static func rotateTo(newDirection:UIInterfaceOrientation) {
        self.current.setValue(newDirection.rawValue, forKey: "orientation")
    }

    static func rotateToIfNeed(newDirection:UIInterfaceOrientation) {
        if !self.isOrientation(toCmpOrientation: newDirection) {
            self.rotateTo(newDirection: newDirection)
        }
    }

    static func isOrientation(toCmpOrientation:UIInterfaceOrientation) -> Bool {
        //Note:
        // self.current.orientation is UIDeviceOrientation
        // toCmpOrientation is UIInterfaceOrientation
        // but first 5 type: unknown/portrait/portraitUpsideDown/landscapeLeft/landscapeRight
        // of enum value is equal
        return self.current.orientation.rawValue == toCmpOrientation.rawValue
    }
}
