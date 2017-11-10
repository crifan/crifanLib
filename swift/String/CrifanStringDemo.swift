//
//  CrifanStringDemo.swift
//  SalesApp
//
//  Created by licrifan on 16/7/16.
//  Copyright © 2016年 licrifan. All rights reserved.
//

import UIKit

/*
 if realBadgeStr.notEmpty {
 
 }
 
 
 let addMoreTitleList = ["Create Group".localized, "Create Topic".localized]
 
 
 var familyNameChar:String = newContactNameStr.firstChar
 
 
 return inputStr.replace("\\\"", to: "\"")
 
 
func genHeaderText(headerName:String) -> String {
//    print("\r\ngenHeaderText")
    var headerText = headerName
    
    if headerName.isEmpty {
        return headerText
    }
    
    if headerName.characters.count <= 1 {
        return headerText
    }
    
    //default use first two char
    let firstTwoChar = (headerName as NSString).substringToIndex(2)
    headerText = firstTwoChar.uppercaseString

    //if all chinese name, get last one cn char
    if headerName.isAllChineseCharacters {
        headerText = headerName.lastChar
    }else if headerName.isAllLetters {
        let firstTwoChar = (headerName as NSString).substringToIndex(2)
        headerText = firstTwoChar.uppercaseString
    }else if headerName.isAllDigits {
        headerText = (headerName as NSString).substringToIndex(2)
    }else if headerName.containsString(" "){
        let removedSpaceName = headerName.replace(" ", to: "")

        if removedSpaceName.isAllLetters {
            let subStrArr:[String] = headerName.splitToStrArr()
            
            let firstStr = subStrArr[0]
            let firstChar = getFirstChar(firstStr)
            
            var mergedTwoChar = firstChar
            
            if subStrArr.count >= 2 {
                let secondStr = subStrArr[1]
                if !secondStr.isEmpty {
                    let sencondChar = getFirstChar(secondStr)
                    mergedTwoChar += sencondChar
                }
            }
            
            headerText = mergedTwoChar.uppercaseString
        }
    }
    
    gLog.debug("\(headerName) -> \(headerText)")
    return headerText
}
 
 let trimmedMsgStr = messageStrToSend.trim()
 
func filterUnsupportChar(originStr:String) ->String {
    var filtedStr = originStr
    
    //filtedStr = filtedStr.decodedHtml
    filtedStr = filtedStr.decodedHtmlEntities
    
    //iOS UITextView not support 200D, so remove it here
    filtedStr = filtedStr.replace("\u{200d}", to: "")
//    print("removed 200d: filtedStr=\(filtedStr)")
    //seems iOS support 00A0, so no need to replace it here
//    filtedStr = filtedStr.replace("\u{00a0}", to: " ")
//    print("replaced 00a0: filtedStr=\(filtedStr)")
    
    return filtedStr
}
 

    let singleStr:String = "张三"
    let firstCharStr:String = singleStr.firstChar
    print("firstCharStr=\(firstCharStr)") //张
    
    /*
    * getLastChar demo
    */
    let singleStr2:String = "张三"
    let lastCharStr:String = singleStr2.lastChar
    print("lastCharStr=\(lastCharStr)") //三
    
    /*
    * splitToCharArr demo
    */
    let stringToSplit:String = "一个字符串"
    let spiltedCharArr:[Character] = stringToSplitsplitToCharArr.()
    print("spiltedCharArr=\(spiltedCharArr)") //["一", "个", "字", "符", "串"]

    /*
    * splitToStrArr demo
    */
    //let noneSeperatorStr:String = ""
    let strWithoutSpace:String = "中间没有空格单个字符串"
    //let splitedStrArr_withoutSpace:[String] = strWithoutSpace.splitToStrArr(noneSeperatorStr)
    let splitedStrArr_withoutSpace:[String] = strWithoutSpace.splitToStrArr()
    print("splitedStrArr_withoutSpace=\(splitedStrArr_withoutSpace)") //["中", "间", "没", "有", "空", "格", "单", "个", "字", "符", "串"]

    let spaceSeperatorStr:String = " "
    let stringContainingSpace:String = "中 间   有  空     格 的 字   符 串 "
    let splitedStrArr_containingSpace:[String] = stringContainingSpace.splitToStrArr(spaceSeperatorStr)
    print("splitedStrArr_containingSpace=\(splitedStrArr_containingSpace)") //["中", "间", "有", "空", "格", "的", "字", "符", "串"]


    /*
    * mergeCharArrToSingleStr demo
    */
    let charArrToMerge:[Character] = ["待", "合", "并", "字", "符", "数", "组"]
    let mergedStr:String = mergeCharArrToSingleStr(charArrToMerge)
    print("mergedStr=\(mergedStr)") //"待合并字符数组"

    /*
    * mergeStrArrToSingleStr demo
    */
    let stringArrToMerge:[String] = ["待", "合", "并", "字", "符", "串","数", "组"]
    let mergedSingleStr:String = mergeStrArrToSingleStr(stringArrToMerge)
    print("mergedSingleStr=\(mergedSingleStr)") //"待合并字符串数组"

    /*
    * translateChineseStrToPinyinWithAccents demo
    */
    let chineseStr:String = "昂山素季"
    let translatedPinyinStrWithAccents:String = translateChineseStrToPinyinWithAccents(chineseStr)
    print("translatedPinyinStrWithAccents=\(translatedPinyinStrWithAccents)") //"áng shān sù jì"

    /*
    * removeAccentsFromStr demo
    */
    let pinyinWithAccents:String = "áng shān sù jì"
    let strippedAccentsPinyin:String = removeAccentsFromStr(pinyinWithAccents)
    print("strippedAccentsPinyin=\(strippedAccentsPinyin)") //"ang shan su ji"

    /*
    * translateChineseStrToCharPinyinDict demo
    */
    let chineseStrToTranslate:String = "昂山素季"
    let translatedCharPinyinDict = translateChineseStrToCharPinyinDict(chineseStrToTranslate)
    print("translatedCharPinyinDict=\(translatedCharPinyinDict)") //[["昂": "ang"], ["山": "shan"], ["素": "su"], ["季": "ji"]]


    func testUrlEncodeDecode(){
        let urlWithZhcn = "http://xx.xx.xx.xx/skrDev/src/report/wholesale.html?t=1510295408712&drAreaFiltrateCode=大东南区&drAreaFiltrateName=大东南区"
        let urlEncodedPercent = "http://xx.xx.xx.xx/skrDev/src/report/wholesale.html?t=1510295408712&drAreaFiltrateCode=%E5%A4%A7%E4%B8%9C%E5%8D%97%E5%8C%BA&drAreaFiltrateName=%E5%A4%A7%E4%B8%9C%E5%8D%97%E5%8C%BA"
        
        let encodedZhcnUrl = urlWithZhcn.encodedUrl
        //encodedZhcnUrl=http://xx.xx.xx.xx/skrDev/src/report/wholesale.html?t=1510295408712&drAreaFiltrateCode=%E5%A4%A7%E4%B8%9C%E5%8D%97%E5%8C%BA&drAreaFiltrateName=%E5%A4%A7%E4%B8%9C%E5%8D%97%E5%8C%BA
        let decoedPercentUrl = urlEncodedPercent.decodedUrl
        print("encodedZhcnUrl=\(encodedZhcnUrl)")
        print("decoedPercentUrl=\(decoedPercentUrl)")
        //decoedPercentUrl=http://xx.xx.xx.xx/skrDev/src/report/wholesale.html?t=1510295408712&drAreaFiltrateCode=大东南区&drAreaFiltrateName=大东南区
    }
 
 */
