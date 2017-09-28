//
//  SelectItemViewController.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/6/15.
//  Copyright © 2016年 licrifan. All rights reserved.
//
// show a list
// allow click to select a single row

import UIKit
import Cartography

let SelectTableViewPaddingX:CGFloat = 15
let SelectTableViewCellHeight:CGFloat = 44

let SelectItemTableViewCellId:String = "SelectItemTableViewCellId"


class SelectItemViewController: TapToHideViewController, UITableViewDelegate, UITableViewDataSource {
    var selectTableView:UITableView
    
    var selectItemList:[String]
    
    var curSelectIdx:Int
    var returnSelectIdx:Int
    
    var completionHadler:((Int) -> Void)?
    
    init(curSelectIdx:Int = Int.InvalidIndex, selectItemList:[String] = [String](), completionHadler:((Int) -> Void)? = nil) {
        gLog.verbose("curSelectIdx=\(curSelectIdx), selectItemList=\(selectItemList), completionHadler=\(completionHadler)")

        self.curSelectIdx = curSelectIdx
        self.selectItemList = selectItemList
        self.selectTableView = UITableView()
        self.completionHadler = completionHadler
        
        self.returnSelectIdx = Int.InvalidIndex
        
        super.init(notHideView: selectTableView)
        
        self.hideVCHandler = self.callCompletionHadler
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.view.backgroundColor = CommonSelectionViewAlphaBkgColor
     
        let rowNum:Int = self.selectItemList.count
        var selectTableViewHeight:CGFloat = SelectTableViewCellHeight * CGFloat(rowNum)
        gLog.verbose("rowNum=\(rowNum), selectTableViewHeight=\(selectTableViewHeight)")
        
        if selectTableViewHeight > ScreenHeight {
           selectTableViewHeight = ScreenHeight
        }

        self.selectTableView.delegate = self
        self.selectTableView.dataSource = self
        self.selectTableView.rowHeight = SelectTableViewCellHeight
        self.selectTableView.layer.cornerRadius = 20
        self.selectTableView.registerClass(UITableViewCell.self, forCellReuseIdentifier: SelectItemTableViewCellId)
        self.view.addSubview(self.selectTableView)
        constrain(self.selectTableView){ selectTableView in
            selectTableView.left   == selectTableView.superview!.left + SelectTableViewPaddingX
            selectTableView.right  == selectTableView.superview!.right - SelectTableViewPaddingX
            selectTableView.height  == selectTableViewHeight
            selectTableView.centerY == selectTableView.superview!.centerY
        }
        
        if self.curSelectIdx.isValidIndex {
           let selectedIndexPath = NSIndexPath(forRow: self.curSelectIdx, inSection: 0)
            gLog.verbose("selectedIndexPath=\(selectedIndexPath) self.curSelectIdx=\(self.curSelectIdx)")

            self.selectTableView.selectRowAtIndexPath(selectedIndexPath, animated: false, scrollPosition: UITableViewScrollPosition.Middle)
        }
    }
    
    /*************************************************************************
     * UITableViewDelegate Functions
     *************************************************************************/
    
    /*************************************************************************
     * UITableViewDataSource Functions
     *************************************************************************/
    
    func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return self.selectItemList.count
    }
    
    func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        gLog.verbose("tableView=\(tableView), indexPath=\(indexPath)")

        let curCell = UITableViewCell(style: UITableViewCellStyle.Default, reuseIdentifier: SelectItemTableViewCellId)
        
        curCell.selectionStyle = .None

        curCell.textLabel?.text = self.selectItemList[indexPath.row]
        curCell.textLabel?.textAlignment = .Left
        constrain(curCell.textLabel!){itemLabel  in
            itemLabel.top == itemLabel.superview!.top
            itemLabel.bottom == itemLabel.superview!.bottom
            itemLabel.left == itemLabel.superview!.left  + SelectTableViewPaddingX
            itemLabel.right == itemLabel.superview!.right - SelectTableViewPaddingX
        }

        if indexPath.row == self.curSelectIdx {
            setSelectedColor(curCell)
        }

        return curCell
    }
    
    func setSelectedColor(curCell:UITableViewCell) {
        curCell.contentView.backgroundColor = CommonButtonColor
        curCell.textLabel?.textColor = UIColor.whiteColor()
    }
    
    func tableView(tableView: UITableView, didSelectRowAtIndexPath indexPath: NSIndexPath){
        gLog.verbose("tableView=\(tableView), indexPath=\(indexPath)")
        
        self.curSelectIdx = indexPath.row
        self.returnSelectIdx = self.curSelectIdx
        gLog.verbose("self.curSelectIdx=\(self.curSelectIdx), self.returnSelectIdx=\(self.returnSelectIdx)")

        self.callCompletionHadlerAndHideVC()
    }
    
    func tableView(tableView: UITableView, didHighlightRowAtIndexPath indexPath: NSIndexPath) {
        gLog.verbose("tableView=\(tableView), indexPath=\(indexPath)")

        if let curCell = tableView.cellForRowAtIndexPath(indexPath) {
            setSelectedColor(curCell)
        }
    }

    /*************************************************************************
     * Current File Functions
     *************************************************************************/

    func callCompletionHadlerAndHideVC(){
        self.callCompletionHadler()

        dispatchMain_async({
            self.dismissViewControllerAnimated(true, completion: nil)
        })
    }
    
    func callCompletionHadler(){
        gLog.verbose("self.curSelectIdx=\(self.curSelectIdx), self.returnSelectIdx=\(self.returnSelectIdx)")
        
        if self.completionHadler != nil {
            self.completionHadler!(self.returnSelectIdx)
        }
    }

}
