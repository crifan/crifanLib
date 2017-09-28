//
//  CrifanDevice.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

public enum DeviceModel: String {
    //case Simulator = "Simulator/sandbox",
    case Simulator = "Simulator",
    iPod1          = "iPod 1",
    iPod2          = "iPod 2",
    iPod3          = "iPod 3",
    iPod4          = "iPod 4",
    iPod5          = "iPod 5",
    iPod6          = "iPod 6",
    iPad1          = "iPad 1",
    iPad2          = "iPad 2",
    iPad3          = "iPad 3",
    iPad4          = "iPad 4",
    iPhone1G       = "iPhone 1G",
    iPhone3G       = "iPhone 3G",
    iPhone3GS      = "iPhone 3GS",
    iPhone4        = "iPhone 4",
    iPhone4S       = "iPhone 4S",
    iPhone5        = "iPhone 5",
    iPhone5S       = "iPhone 5S",
    iPhone5C       = "iPhone 5C",
    iPadMini1      = "iPad Mini 1",
    iPadMini2      = "iPad Mini 2",
    iPadMini3      = "iPad Mini 3",
    iPadMini4      = "iPad Mini 4",
    iPadAir1       = "iPad Air 1",
    iPadAir2       = "iPad Air 2",
    iPadPro        = "iPad Pro",
    iPhone6        = "iPhone 6",
    iPhone6plus    = "iPhone 6 Plus",
    iPhone6S       = "iPhone 6S",
    iPhone6Splus   = "iPhone 6S Plus",
    iPhoneSE       = "iPhone SE",
    AppleWatch     = "Apple Watch",
    AppleTV        = "Apple TV",
    Unknown        = "Unknown"
}

extension UIDevice {
//    public var curDeviceType: DeviceModel {
    var curDeviceType: DeviceModel {
        var systemInfo = utsname()
        uname(&systemInfo)
        let modelCode = withUnsafeMutablePointer(&systemInfo.machine) {
            ptr in String.fromCString(UnsafePointer<CChar>(ptr))
        }
        print("modelCode=\(modelCode)")
        //modelCode=Optional("x86_64")
        //modelCode=Optional("iPhone7,2")
        var modelMap : [ String : DeviceModel ] = [
            "i386"      : .Simulator,
            "x86_64"    : .Simulator,

            "iPod1,1"   : .iPod1,
            "iPod2,1"   : .iPod2,
            "iPod3,1"   : .iPod3,
            "iPod4,1"   : .iPod4,
            "iPod5,1"   : .iPod5,
            "iPod7,1"   : .iPod6,

            "iPad1,1"   : .iPad1,
            "iPad2,1"   : .iPad2,
            "iPad2,2"   : .iPad2,
            "iPad2,3"   : .iPad2,
            "iPad2,4"   : .iPad2,
            "iPad3,1"   : .iPad3,
            "iPad3,2"   : .iPad3,
            "iPad3,3"   : .iPad3,
            "iPad3,4"   : .iPad4,
            "iPad3,5"   : .iPad4,
            "iPad3,6"   : .iPad4,
            "iPad4,1"   : .iPadAir1,
            "iPad4,2"   : .iPadAir1,
            "iPad4,3"   : .iPadAir1,
            "iPad5,3"   : .iPadAir2,
            "iPad5,4"   : .iPadAir2,
            "iPad6,3"   : .iPadPro,
            "iPad6,4"   : .iPadPro,
            "iPad6,7"   : .iPadPro,
            "iPad6,8"   : .iPadPro,
            "iPad2,5"   : .iPadMini1,
            "iPad2,6"   : .iPadMini1,
            "iPad2,7"   : .iPadMini1,
            "iPad4,4"   : .iPadMini2,
            "iPad4,5"   : .iPadMini2,
            "iPad4,6"   : .iPadMini2,
            "iPad4,7"   : .iPadMini3,
            "iPad4,8"   : .iPadMini3,
            "iPad4,9"   : .iPadMini3,
            "iPad5,1"   : .iPadMini4,
            "iPad5,2"   : .iPadMini4,
            
            "iPhone1,1" : .iPhone1G,
            "iPhone1,2" : .iPhone3G,
            "iPhone2,1" : .iPhone3GS,
            "iPhone3,1" : .iPhone4,
            "iPhone3,2" : .iPhone4,
            "iPhone3,3" : .iPhone4,
            "iPhone4,1" : .iPhone4S,
            "iPhone5,1" : .iPhone5,
            "iPhone5,2" : .iPhone5,
            "iPhone5,3" : .iPhone5C,
            "iPhone5,4" : .iPhone5C,
            "iPhone6,1" : .iPhone5S,
            "iPhone6,2" : .iPhone5S,
            "iPhone7,1" : .iPhone6plus,
            "iPhone7,2" : .iPhone6,
            "iPhone8,1" : .iPhone6S,
            "iPhone8,2" : .iPhone6Splus,
            "iPhone8,4" : .iPhoneSE,
            
            "Watch1,1"  : .AppleWatch,
            "Watch1,2"  : .AppleWatch,
            
            "AppleTV2,1" : .AppleTV,
            "AppleTV3,1" : .AppleTV,
            "AppleTV3,2" : .AppleTV,
            "AppleTV5,3" : .AppleTV,
        ]
        
        if let model = modelMap[String.fromCString(modelCode!)!] {
            print("model=\(model)")
            //model=Simulator
            //model=iPhone6
            return model
        }

        return DeviceModel.Unknown
    }
    
    public var isPhone:Bool {
        return self.curDeviceType.rawValue.containsString("iPhone")
    }
    
    public var isPad:Bool {
        return self.curDeviceType.rawValue.containsString("iPad")
    }

    public var isPod:Bool {
        return self.curDeviceType.rawValue.containsString("iPod")
    }
    
    public var isSimulator:Bool {
        return self.curDeviceType.rawValue.containsString("Simulator")
    }

    static func rotateTo(newDirection:UIInterfaceOrientation) {
        self.current.setValue(newDirection.rawValue, forKey: "orientation")
    }
}
