//
//  ImagePickerViewController.swift
//  CrifanLibSwift
//
//  Created by licrifan on 16/6/25.
//  Copyright © 2016年 licrifan. All rights reserved.
//
// allow to choose/pick/choose image/picture from galary/album
// and take a photo

import UIKit

class ImagePickerViewController: UIViewController, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
    var selectPictureAlertController:UIAlertController
    
    var pickedImage:UIImage
    var scaledImage:UIImage
    var attachmentIdList:[String]

    var pickImageCompletionHandler:((pickedImage:UIImage) -> Void)?

    init(pickImageCompletionHandler:((pickedImage:UIImage) -> Void)? = nil){
        self.pickImageCompletionHandler = pickImageCompletionHandler

        self.selectPictureAlertController = UIAlertController()

        self.pickedImage = UIImage()
        self.scaledImage = UIImage()
        self.attachmentIdList = [String]()

        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.view.backgroundColor = UIColor.clearColor()
    }
    
    override func viewWillAppear(animated: Bool) {
        super.viewWillAppear(animated)
    }
    
    override func viewDidAppear(animated: Bool) {
        super.viewDidAppear(animated)
        
        gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
        
        guard self.selectPictureAlertController.actions.isEmpty else {
            gLog.verbose("already added alert actions")

            return
        }
        
        self.selectPictureAlertController = UIAlertController(title: "提示", message: "", preferredStyle: UIAlertControllerStyle.ActionSheet)
        let cancelAlertAction = UIAlertAction(title: "取消", style: .Cancel, handler: self.cancelImagePick(_:))
        selectPictureAlertController.addAction(cancelAlertAction)
        
        let localAlbumAlertAction = UIAlertAction(title: "打开本地相册", style: UIAlertActionStyle.Default, handler:self.openLocalAlbum(_:))
        selectPictureAlertController.addAction(localAlbumAlertAction)
        
        let openCameraAlertAction = UIAlertAction(title: "打开相机", style: UIAlertActionStyle.Default, handler: self.openCamera(_:))
        selectPictureAlertController.addAction(openCameraAlertAction)
        
        selectPictureAlertController.modalPresentationStyle = .Custom
        
        gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
        //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=nil, self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
        
        //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=nil, self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
        
        self.presentViewController(selectPictureAlertController, animated: true, completion: nil)
        
        gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
        //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=nil, self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
        
        //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=Optional(<UIAlertController: 0x7ab89c00>), self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
    }
    
    /*************************************************************************
     * Cancel Select Image
     *************************************************************************/
    func cancelImagePick(alerAction:UIAlertAction){
        gLog.verbose("alerAction=\(alerAction)")
        
        self.dissmissCurrentVC()
    }
    
    /*************************************************************************
     * Open Local Album
     *************************************************************************/
    func openLocalAlbum(alerAction:UIAlertAction){
        gLog.verbose("alerAction=\(alerAction)")
        
        gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
        //self=<Sales_App.ImagePickerViewController: 0x7df92970>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x7deb2e20>), self.presentedViewController=nil, self.presentingViewController=Optional(<UINavigationController: 0x7c27c400>)

        let imagePicker:UIImagePickerController = UIImagePickerController()
        gLog.verbose("imagePicker=\(imagePicker)")
        imagePicker.delegate = self
        self.presentViewController(imagePicker, animated: true, completion: nil)
    }
    
    //UIImagePickerControllerDelegate
    
    func imagePickerController(picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [String : AnyObject]) {
        gLog.verbose("picker=\(picker), info=\(info)")
        //picker=<UIImagePickerController: 0x7c99c400>, info=["UIImagePickerControllerOriginalImage": <UIImage: 0x7b735b60> size {3000, 2002} orientation 0 scale 1.000000, "UIImagePickerControllerReferenceURL": assets-library://asset/asset.JPG?id=ED7AC36B-A150-4C38-BB8C-B6D696F4F2ED&ext=JPG, "UIImagePickerControllerMediaType": public.image]
        //picker=<UIImagePickerController: 0x7a247800>, info=["UIImagePickerControllerOriginalImage": <UIImage: 0x79e04900> size {3000, 2002} orientation 0 scale 1.000000, "UIImagePickerControllerReferenceURL": assets-library://asset/asset.JPG?id=9F983DBA-EC35-42B8-8773-B597CF782EDD&ext=JPG, "UIImagePickerControllerMediaType": public.image]
        /*
picker=<UIImagePickerController: 0x1369b3800>, info=["UIImagePickerControllerMediaType": public.image, "UIImagePickerControllerOriginalImage": <UIImage: 0x137c26cb0> size {2448, 3264} orientation 3 scale 1.000000, "UIImagePickerControllerMediaMetadata": {
    DPIHeight = 72;
    DPIWidth = 72;
    Orientation = 6;
    "{Exif}" =     {
        ApertureValue = "2.27500704749987";
        BrightnessValue = "3.72325942409352";
        ColorSpace = 1;
        DateTimeDigitized = "2016:06:27 15:51:35";
        DateTimeOriginal = "2016:06:27 15:51:35";
        ExposureBiasValue = 0;
        ExposureMode = 0;
        ExposureProgram = 2;
        ExposureTime = "0.0303030303030303";
        FNumber = "2.2";
        Flash = 24;
        FocalLenIn35mmFilm = 29;
        FocalLength = "4.15";
        ISOSpeedRatings =         (
            50
        );
        LensMake = Apple;
        LensModel = "iPhone 6 back camera 4.15mm f/2.2";
        LensSpecification =         (
            "4.15",
            "4.15",
            "2.2",
            "2.2"
        );
        MeteringMode = 3;
        PixelXDimension = 3264;
        PixelYDimension = 2448;
        SceneType = 1;
        SensingMethod = 2;
        ShutterSpeedValue = "5.060000179460458";
        SubjectArea =         (
            1917,
            1336,
            610,
            612
        );
        SubsecTimeDigitized = 274;
        SubsecTimeOriginal = 274;
        WhiteBalance = 0;
    };
    "{MakerApple}" =     {
        1 = 4;
        14 = 0;
        2 = <11000e00 09000900 3f007e00 63000601 c500c100 9f009900 8e009900 ac00bd00 14001100 0b001a00 7c006c00 6800af00 a900c900 1b01bd00 90009800 a800b200 16001a00 19002600 18017500 5e008800 df00ea00 1401ba00 8b009800 a400af00 69004900 7a009800 d100ba00 93008a00 3900ce00 1001b700 86008a00 a300b900 c6007300 84002d00 2b007700 78005f00 5000ce00 0e01ae00 8500d100 9200ad00 ad006d00 81002900 29008400 99005500 4300d700 1401ed00 4f010701 9400a300 11005800 87002d00 2e009200 ae005400 3f00d300 0401a600 14001200 7e00a400 20006300 95003200 32009c00 ba005800 3900cb00 0901bb00 14001200 8100a700 31006800 9c003900 3300a400 b6005a00 3c00d500 1601bd00 14001400 8400a000 36006900 95003f00 3b00b500 b5005e00 4100e100 2501c600 14001700 8300ab00 39006500 d100b100 d1002601 f4006f00 4700e800 3301cd00 15001c00 8600ad00 38006700 43018701 bb01d301 59017400 63001901 5c01ff00 2c002000 9100b900 3b006a00 32016c01 a801c001 44018a00 82003001 8d014701 85016e01 a200c700 49006200 dc00f100 1b013401 e500b400 38003e01 a7011901 b000cd00 b900cf00 5c004800 7c00e500 78006c00 6900f200 00015801 c1012c01 b400ae00 c500cb00 61003200 65003701 72005300 45009300 2f019201 d9014401 bb00bd00 bf00cb00>;
        20 = 4;
        3 =         {
            epoch = 0;
            flags = 1;
            timescale = 1000000000;
            value = 13495992547916;
        };
        4 = 1;
        5 = 173;
        6 = 168;
        7 = 1;
        8 =         (
            "0.00238734",
            "-0.820809",
            "-0.5356817"
        );
        9 = 275;
    };
    "{TIFF}" =     {
        DateTime = "2016:06:27 15:51:35";
        Make = Apple;
        Model = "iPhone 6";
        ResolutionUnit = 2;
        Software = "9.3.2";
        XResolution = 72;
        YResolution = 72;
    };
}]
         */

        if let pickedImage = info[UIImagePickerControllerOriginalImage] {
            gLog.verbose("pickedImage=\(pickedImage)")
            //pickedImage=<UIImage: 0x7d84c780> size {4288, 2848} orientation 0 scale 1.000000
            //pickedImage=<UIImage: 0x137c26cb0> size {2448, 3264} orientation 3 scale 1.000000

            self.noticeInfo("已选择图片", autoClear: true, autoClearTime: 1)
            
            self.pickedImage = pickedImage as! UIImage
            
            self.dissmissCurrentVC()
        } else {
            self.noticeInfo("找不到所选图片", autoClear: true, autoClearTime: 1)
            
            self.dissmissCurrentVC()
        }
    }
    
    func imagePickerControllerDidCancel(picker: UIImagePickerController){
        gLog.verbose("picker=\(picker)")
        
        self.dissmissCurrentVC()
    }
    
    func dissmissCurrentVC() {
        gLog.verbose("")

        gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
        //self=<Sales_App.ImagePickerViewController: 0x7be90330>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x7becccf0>), self.presentedViewController=Optional(<UIImagePickerController: 0x7c168c00>), self.presentingViewController=Optional(<UINavigationController: 0x7a9a1800>)
        //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=Optional(<UIImagePickerController: 0x7a454e00>), self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
        self.dismissViewControllerAnimated(false, completion: {
            gLog.verbose("self=\(self), self.parentViewController=\(self.parentViewController), self.presentationController=\(self.presentationController), self.presentedViewController=\(self.presentedViewController), self.presentingViewController=\(self.presentingViewController)")
            //self=<Sales_App.ImagePickerViewController: 0x7be90330>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x7becccf0>), self.presentedViewController=nil, self.presentingViewController=Optional(<UINavigationController: 0x7a9a1800>)
            
            //self=<Sales_App.ImagePickerViewController: 0x797567f0>, self.parentViewController=nil, self.presentationController=Optional(<UIPresentationController: 0x79759d10>), self.presentedViewController=Optional(<UIAlertController: 0x7ab89c00>), self.presentingViewController=Optional(<UINavigationController: 0x7b31d000>)
            

//            if self.presentedViewController != nil {
                self.dismissViewControllerAnimated(false, completion: nil)
//            }
            
            if self.pickImageCompletionHandler != nil {
                self.pickImageCompletionHandler!(pickedImage: self.pickedImage)
            }
            
            //self.selectPictureAlertController.dismissViewControllerAnimated(false, completion: nil)
            
//            if self.parentVC != nil {
//                gLog.verbose("self.parentVC.presentedViewController=\(self.parentVC!.presentedViewController)")
//                //self.parentVC.presentedViewController=Optional(<Sales_App.ImagePickerViewController: 0x12faa2370>)
//
//                if self.parentVC!.presentedViewController != nil {
//                    self.parentVC!.dismissViewControllerAnimated(false, completion: nil)
//                }
//            }
        })
        
    }
    
    /*************************************************************************
     * Opem Local Camera
     *************************************************************************/
    func openCamera(alerAction:UIAlertAction)  {
        gLog.verbose("alerAction=\(alerAction)")

        if UIImagePickerController.isSourceTypeAvailable(.Camera){
            let picker = UIImagePickerController()
            picker.delegate = self
            picker.sourceType = UIImagePickerControllerSourceType.Camera
            picker.allowsEditing = false

            self.presentViewController(picker, animated: true, completion: nil)
        }else{
            self.noticeError("找不到相机", autoClear: true)
            
            self.dissmissCurrentVC()
        }
    }
    
}