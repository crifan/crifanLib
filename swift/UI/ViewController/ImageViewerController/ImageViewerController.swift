//
//  ImageViewerController.swift
//  CrifanLibSwift
//
//  Created by Crifan Li on 16/6/30.
//  Copyright © 2016年 licrifan. All rights reserved.
//
// show image
// double to zoom in
// when exceed max size to back to fit size
// allow pinch to scroll

import UIKit

class ImageViewerController: UIViewController, UIScrollViewDelegate {
    var curImage:UIImage
    
    var imageView: UIImageView
    
    var scrollView:UIScrollView
    
    init(originImage:UIImage) {
        self.curImage = originImage
        self.imageView = UIImageView(image: self.curImage)
        
        self.scrollView = UIScrollView()
        
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.backgroundColor = UIColor(hexString: "#999999", alpha: 0.5)!
        
        self.scrollView.addSubview(self.imageView)
        self.view.addSubview(self.scrollView)
        
        self.scrollView.frame = CGRectMake(
            0,
            0,
            self.view.frame.width,
            self.view.frame.height - 0
        )
        
        let imageSize = self.imageView.image!.size
        //        print("imageSize=\(imageSize)") //(1359.0, 901.0)
        
        self.scrollView.contentSize = imageSize
        
        self.scrollView.bounces = false
        self.scrollView.showsHorizontalScrollIndicator = false
        self.scrollView.showsVerticalScrollIndicator = false
        self.scrollView.userInteractionEnabled = true
        self.scrollView.delegate = self
        self.scrollView.bouncesZoom = false
        self.scrollView.scrollsToTop = false
        self.scrollView.backgroundColor = UIColor.blackColor()
        let scrollViewFrame = scrollView.frame
        //        print("scrollViewFrame=\(scrollViewFrame)") //(0.0, 0.0, 375.0, 667.0)
        let scaleWidth = scrollViewFrame.size.width / scrollView.contentSize.width
        //        print("scaleWidth=\(scaleWidth)") //0.275938189845475
        let scaleHeight = scrollViewFrame.size.height / scrollView.contentSize.height
        //        print("scaleHeight=\(scaleHeight)") //0.740288568257492
        let minScale = min(scaleWidth, scaleHeight)
        //        print("minScale=\(minScale)") //0.275938189845475
        
        self.scrollView.minimumZoomScale = minScale
        self.scrollView.maximumZoomScale = 1.0
        self.scrollView.zoomScale = minScale
        
        centerScrollViewContents()
        
        let doubleTap = UITapGestureRecognizer(target: self, action: #selector(self.doubleTapped(_:)))
        doubleTap.numberOfTapsRequired = 2
        doubleTap.numberOfTouchesRequired = 1
        self.scrollView.addGestureRecognizer(doubleTap)
        
        let singleTap = UITapGestureRecognizer(target: self, action: #selector(self.singleTap(_:)))
        singleTap.numberOfTapsRequired = 1
        singleTap.numberOfTouchesRequired = 1
        self.scrollView.addGestureRecognizer(singleTap)
        singleTap.requireGestureRecognizerToFail(doubleTap)
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
    
    func centerScrollViewContents() {
        let boundsSize = self.scrollView.bounds.size
        //        print("boundsSize=\(boundsSize)")
        var contentsFrame = self.imageView.frame
        //        print("contentsFrame=\(contentsFrame)")
        
        if contentsFrame.size.width < boundsSize.width {
            contentsFrame.origin.x = (boundsSize.width - contentsFrame.size.width) / 2.0
        } else {
            contentsFrame.origin.x = 0.0
        }
        
        if contentsFrame.size.height < boundsSize.height {
            contentsFrame.origin.y = (boundsSize.height - contentsFrame.size.height) / 2.0
        } else {
            contentsFrame.origin.y = 0.0
        }
        
        //        print("contentsFrame=\(contentsFrame)")
        self.imageView.frame = contentsFrame
    }
    
    func viewForZoomingInScrollView(scrollView: UIScrollView) -> UIView? {
        return self.imageView
    }
    
    func scrollViewDidZoom(scrollView: UIScrollView) {
        centerScrollViewContents()
    }
    
    func doubleTapped(recognizer: UITapGestureRecognizer) {
        if (self.scrollView.zoomScale == self.scrollView.maximumZoomScale) {
            self.scrollView.setZoomScale(self.scrollView.minimumZoomScale, animated: true)
        } else {
            let pointInView = recognizer.locationInView(self.imageView)
            //            print("pointInView=\(pointInView)") //(898.155653734425, 425.882443769075)
            
            var newZoomScale = scrollView.zoomScale * 1.5
            //            print("newZoomScale=\(newZoomScale)") //0.986187634979701
            
            newZoomScale = min(newZoomScale, scrollView.maximumZoomScale)
            //            print("newZoomScale=\(newZoomScale)") //0.986187634979701
            
            let scrollViewSize = scrollView.bounds.size
            //            print("scrollViewSize=\(scrollViewSize)") //(375.0, 603.0)
            
            let w = scrollViewSize.width / newZoomScale
            let h = scrollViewSize.height / newZoomScale
            let x = pointInView.x - (w / 2.0)
            let y = pointInView.y - (h / 2.0)
            
            let rectToZoomTo = CGRectMake(x, y, w, h);
            //            print("rectToZoomTo=\(rectToZoomTo)") //(708.029562766088, 120.159689491989, 380.252181936674, 611.445508554172)
            
            scrollView.zoomToRect(rectToZoomTo, animated: true)
        }
    }
    
    func singleTap(recognizer:UITapGestureRecognizer){
        dispatchMain_async({
            self.dismissViewControllerAnimated(true, completion: nil)
        })
    }
    
}

