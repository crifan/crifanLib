//
//  CrifanViewController.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

/***************************************************************************
 * View Functions
 ***************************************************************************/

extension UIApplication {
    class func topViewController(_ base: UIViewController? = UIApplication.shared.keyWindow?.rootViewController) -> UIViewController? {
        if let nav = base as? UINavigationController {
            return topViewController(nav.visibleViewController)
        }
        if let tab = base as? UITabBarController {
            if let selected = tab.selectedViewController {
                return topViewController(selected)
            }
        }
        if let presented = base?.presentedViewController {
            return topViewController(presented)
        }
        return base
    }
    
    class var topViewControllerInStack: UIViewController? {
        var topVcInStack:UIViewController? = nil
        
        if let rootVc = UIApplication.shared.keyWindow?.rootViewController {
            if rootVc is UINavigationController {
                let rootNavi = rootVc as! UINavigationController
                if let lastVc = rootNavi.viewControllers.last {
                    //<Sales_App.SendMessageViewController: 0x14e46a0e0>
                    topVcInStack = lastVc
                }
            }
        }
        
        return topVcInStack
    }
}

extension UIViewController {
    var isCurrentShowing: Bool {
        print("self=\(self)")
        //self=<JianDao.MessageTableViewController: 0x7a900680>
        
        var isCurrentShow = false
        
        //check whether is current showing UI
        if let topVC = UIApplication.topViewController() {
            //        print("topVC=\(topVC)")
            //topVC=<JianDao.ConversationViewController: 0x7a99f280>
            
            if topVC == self {
                isCurrentShow = true
            }
        }
        
        return isCurrentShow
    }

    func showAlert(_ title:String, message:String? = nil) {
//        print("title=\(title), message=\(message)")
        
        dispatchMain_async({
            let alertController = UIAlertController(title: title, message: message, preferredStyle: UIAlertControllerStyle.alert)
            let sureAlertAction = UIAlertAction(title: "确定", style: UIAlertActionStyle.destructive, handler: nil)
            alertController.addAction(sureAlertAction)
            
            if self.isCurrentShowing {
                print("self=\(self)")
                self.present(alertController, animated: true, completion: nil)
            }
        })
    }

    func getCallerViewController() -> UIViewController? {
        var calerVc:UIViewController? = nil
        
        if let naviViewControllers = self.navigationController?.viewControllers{
            if let lastVc = naviViewControllers.last {
                calerVc = lastVc
                //Optional(<JianDao.ConversationManageViewController: 0x7facfd93a870>)
            }
        }
        
        return calerVc
    }
    
    var hasExisted: Bool {
        var existedVc = false
        if let naviController = self.navigationController{
            for eachVc in naviController.viewControllers {
                if eachVc == self {
                    print("found self=\(self) in navi viewControllers")
                    existedVc = true
                    break
                }
            }
        }
        
        return existedVc
    }
    
    func doShowViewController(_ vcToShow:UIViewController) {
        print("self=\(self), vcToShow=\(vcToShow)")
        //doShowViewController self=<JianDao.PersonInfoViewController: 0x7aeebe10>, vcToShow=<JianDao.MessageTableViewController: 0x79f80b80>
        
        if vcToShow.hasExisted {
            //pop to that view controller
            //print("curVc.navigationController?.viewControllers=\(curVc.navigationController?.viewControllers)")
            _ = self.navigationController?.popToViewController(vcToShow, animated: true)
            //            print("curVc.navigationController?.viewControllers=\(curVc.navigationController?.viewControllers)")
        } else {
            self.show(vcToShow, sender: self)
        }
    }
    
    func modelPresentViewController(_ vcToShow:UIViewController, animated:Bool = true, forceInMainThread:Bool = false) {
        print("vcToShow=\(vcToShow), animated=\(animated), forceInMainThread=\(forceInMainThread)")
        
        vcToShow.modalPresentationStyle = .custom
        
        if forceInMainThread {
            //sometime for workaround a bug, such as:
            //http://openradar.appspot.com/19563577
            //need run in main thread
            dispatchMain_async({
                self.present(vcToShow, animated: animated, completion: nil)
            })
        } else {
            self.present(vcToShow, animated: animated, completion: nil)
        }
    }
}

