//
//  GridViewDemo.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/7/3.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit


class GridViewDemo {
/*
    import Alamofire
    import SwiftyJSON

    class SalesPerfomanceReportViewController: UIViewController {
        
        let SalesPerfomanceRowTitleList:[String] = [
            "顾问",
            "基盘",
            "下订",
            "成交",
            "战败",
            "订单率",
            "成交率",
            ]
        
        var gridView:GridView
        var contentList:[[String]]
        
        let VisibleColumnNum = 5
        let itemHeight:CGFloat = 30
        
        var salesPerformanceList:[[String]]
        
        init(){
            self.contentList = [[String]]()
            self.gridView = GridView()
            
            super.init(nibName: nil, bundle: nil)
            
            self.checkSalesPerfomance()
            
            self.resetGridview()
        }
        
        required init?(coder aDecoder: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }
        
        /*************************************************************************
         * View Controller Functions
         *************************************************************************/
        
        override func viewDidLoad() {
            super.viewDidLoad()
            
            self.title = "销售业绩报表"
            
            self.view.backgroundColor = AppBackgoundColor
            
            self.view.addSubview(self.gridView)
        }
        
        func checkSalesPerfomance(){
            if salesPerformanceList.isEmpty {
                
                salesPerformanceList = self.initSalesPerfomanceList()
                
                getUrlRespDataJson_async(
                    .GET,
                    url: ServerApi.getSalesPerformanceUrl(gCurUserItem.id),
                    respJsonHandler: self.getSalesPerfomanceHandler)
            }
        }
        
        func initSalesPerfomanceList() -> [[String]] {
            var contentList = Array(count: 1, repeatedValue: Array(count: SalesPerfomanceRowTitleList.count, repeatedValue: ""))
            
            contentList[0] = SalesPerfomanceRowTitleList
            
            return contentList
        }
        
        func getSalesPerfomanceHandler(respDataJson:Alamofire.Result<JSON, NSError>, mergedAllPara:Dictionary<String, AnyObject>) {
            gLog.verbose("respDataJson.debugDescription=\(respDataJson.debugDescription)")
            
            switch respDataJson {
            case .Success(let dataJson):
                gLog.verbose("dataJson=\(dataJson)")
                
                guard let salesPerformanceJsonArr = dataJson.array else {
                    gLog.error("get empty sales perfomance data")
                    
                    return
                }
                
                var curSalesPerformanceList  = self.initSalesPerfomanceList()
                gLog.verbose("curSalesPerformanceList=\(curSalesPerformanceList)")
                //curSalesPerformanceList=[["顾问", "基盘", "下订", "成交", "战败", "订单率", "成交率"]]
                
                for eachSalesPerformanceJson in salesPerformanceJsonArr {
                    gLog.verbose("eachSalesPerformanceJson=\(eachSalesPerformanceJson)")
                    
                    let curPerformanceItem = parseJsonToSalesPerformanceItem(eachSalesPerformanceJson)
                    gLog.verbose("curPerformanceItem=\(curPerformanceItem)")
                    
                    curSalesPerformanceList.append(curPerformanceItem)
                }
                
                gCurUserItem.salesPerformanceList = curSalesPerformanceList
                gLog.verbose("gCurUserItem.salesPerformanceList=\(gCurUserItem.salesPerformanceList)")
                
                dispatchMain_async({
                    self.resetGridview()
                    self.view.addSubview(self.gridView)
                })
                
            case .Failure(let error):
                gLog.verbose("error=\(error)")
            }
        }
        
        func resetGridview() {
            self.gridView.removeFromSuperview()
            
            let eachItemSize = CGSize(width: ScreenWidth/CGFloat(VisibleColumnNum), height: itemHeight)
            gLog.verbose("eachItemSize=\(eachItemSize)")
            let columnItemSizeList = Array(count: SalesPerfomanceRowTitleList.count, repeatedValue: eachItemSize)
            gLog.verbose("columnItemSizeList=\(columnItemSizeList)")
            
            self.contentList = gCurUserItem.salesPerformanceList
            self.gridView = GridView(columnItemSizeList: columnItemSizeList, contentList: self.contentList)
        }
        
        
    }

*/
}