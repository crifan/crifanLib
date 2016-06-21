//
//  CrifanInt.swift
//  SalesApp
//
//  Created by licrifan on 16/6/21.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

extension Int {
    @nonobjc static let InvalidIndex:Int = -1
    
    //when some value is index, should be >=0, should not < 0
    var isValidIndex: Bool {
        return (self >= 0)
    }

    @nonobjc static let InvalidId:Int = 0

    //when some value is id -> means can not be 0, should > 0
    var isValidId: Bool {
        return (self > 0)
    }
}
