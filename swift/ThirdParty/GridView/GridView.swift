//
//  GridView.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/6/30.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

class GridView: UICollectionView, UICollectionViewDataSource, UICollectionViewDelegate {
    var columnItemSizeList:[CGSize]
    var contentList:[[String]]
    
    var gridViewLayout:CustomCollectionViewLayout
    
//    var rowLabelBackgroundColor:
//    var columnLabelBackgroundColor:
    
    init(columnItemSizeList:[CGSize] = [CGSize](), contentList:[[String]] = [[String]]()) {
        gLog.verbose("columnItemSizeList=\(columnItemSizeList), columnItemSizeList.count=\(columnItemSizeList.count), contentList=\(contentList)")

        self.columnItemSizeList = columnItemSizeList
        self.contentList = contentList

        let gridViewFrame:CGRect = CGRectMake(
            0,
            0,
            ScreenWidth,
            ScreenHeight - (SingletonRootNC().navigationBar.frame.height + UIApplication.sharedApplication().statusBarFrame.height))
        gLog.verbose("gridViewFrame=\(gridViewFrame)")
        //gridViewFrame=(0.0, 0.0, 320.0, 504.0)
        
        //grid view layout
        self.gridViewLayout = CustomCollectionViewLayout()

        if contentList.notEmpty {
            let firstRowTitleList = contentList[0]
            self.gridViewLayout.numberOfColumns = firstRowTitleList.count
        } else {
            self.gridViewLayout.numberOfColumns = 0
        }
        self.gridViewLayout.columnItemSizeList = columnItemSizeList
        
        super.init(frame: gridViewFrame, collectionViewLayout: gridViewLayout)

        gLog.verbose("self.gridViewLayout.numberOfColumns=\(self.gridViewLayout.numberOfColumns)")

        self.registerClass(GridCell.self, forCellWithReuseIdentifier: GridCellId)
        
        self.backgroundColor = UIColor.whiteColor()
        
        self.delegate = self
        self.dataSource = self
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    /*************************************************************************
     * UICollectionViewDataSource Functions
     *************************************************************************/
    
    //row
    func numberOfSectionsInCollectionView(collectionView: UICollectionView) -> Int {
        return self.contentList.count
    }
    
    //column
    func collectionView(collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        var curItemNum = 0
        if section < self.contentList.count {
            curItemNum = self.contentList[section].count
        }

        gLog.verbose("section=\(section) -> curItemNum=\(curItemNum)")

        return curItemNum
    }
    
    func collectionView(collectionView: UICollectionView, cellForItemAtIndexPath indexPath: NSIndexPath) -> UICollectionViewCell {
        gLog.verbose("collectionView=\(collectionView)")
        
        if indexPath.section == 0 {
            let horizontalTitleCell = collectionView.dequeueReusableCellWithReuseIdentifier(GridCellId, forIndexPath: indexPath) as! GridCell
            
            horizontalTitleCell.configCell(ReportCellLabelFont, contentLabelTextColor: CommonTextColorBlack, cellBackgroundColor: ReportLabelHorizontalBackgroundColor)
            
            var curHorizontalTitle = ""
            
            //row 0
            if indexPath.section < self.contentList.count {
                let firstRowTitleList = self.contentList[indexPath.section]
                
                if indexPath.row < firstRowTitleList.count {
                    curHorizontalTitle = firstRowTitleList[indexPath.row]
                }
            }
            
            gLog.verbose("indexPath=\(indexPath) -> curHorizontalTitle=\(curHorizontalTitle)")

            horizontalTitleCell.contentLabel.text = curHorizontalTitle
            
            return horizontalTitleCell
        } else {
            if indexPath.row == 0 {
                let verticalTitleCell = collectionView.dequeueReusableCellWithReuseIdentifier(GridCellId, forIndexPath: indexPath) as! GridCell
                
                verticalTitleCell.configCell(ReportCellLabelFont, contentLabelTextColor: CommonTextColorBlack, cellBackgroundColor: ReportLabelVerticalBackgroundColor)
                
                var curRowFirstColumnTitle = ""

                //column 0
                if indexPath.section < self.contentList.count {
                    let curRowContentList = self.contentList[indexPath.section]
                    
                    if curRowContentList.count > 0 {
                        curRowFirstColumnTitle = curRowContentList[0]
                    }
                }
                
                verticalTitleCell.contentLabel.text = curRowFirstColumnTitle
                
                gLog.verbose("indexPath=\(indexPath) -> curRowFirstColumnTitle=\(curRowFirstColumnTitle)")

                return verticalTitleCell
            } else {
                let contentCell = collectionView .dequeueReusableCellWithReuseIdentifier(GridCellId, forIndexPath: indexPath) as! GridCell
                
                contentCell.configCell(GridCellContentLabelFont, contentLabelTextColor: GridCellContentLabelTextColor, cellBackgroundColor: GridCellBackgroundColor)
                
                var curContentStr = ""
                
                //for each row
                if indexPath.section < self.contentList.count {
                    let curRowContentList = self.contentList[indexPath.section]
                    gLog.verbose("curRowContentList=\(curRowContentList)")
                    
                    //for each column
                    if indexPath.row < curRowContentList.count {
                        curContentStr = curRowContentList[indexPath.row]
                    }
                }
                
                contentCell.contentLabel.text = curContentStr
                
                gLog.verbose("indexPath=\(indexPath) -> curContentStr=\(curContentStr)")

                return contentCell
            }
        }
    }
    
    func updateContentList(newContentList:[[String]]) {
        gLog.verbose("newContentList")

        self.contentList = newContentList
        
        dispatchMain_async({
            if self.contentList.notEmpty {
                let firstRowTitleList = self.contentList[0]
                self.gridViewLayout.numberOfColumns = firstRowTitleList.count
            }

            self.gridViewLayout.prepareLayout()
            
            self.reloadData()
        })
    }

    
}
