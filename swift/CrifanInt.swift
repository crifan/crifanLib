//
//  CrifanInt.swift
//  Crifan Li
//  Updated: 2017/09/28
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

@discardableResult
func genSizeStr(_ sizeInBytes:Int64, unitSize:Int64 = 0, sizeFormat:String = "") -> String {
    let sizeB:Int64 = 1
    let sizeKB:Int64 = 1024
    let sizeMB:Int64 = sizeKB * 1024
    let sizeGB:Int64 = sizeMB * 1024
    let sizeTB:Int64 = sizeGB * 1024
    let sizePB:Int64 = sizeTB * 1024
    
    //    print("\(Int16.max)") //32767
    //    print("\(Int32.max)") //2147483647
    //    print("\(Int64.max)") //9223372036854775807
    //    print("\(Int.max)")   //9223372036854775807
    
    var sizeStr = ""
    var curUnitSize = unitSize
    var curSizeFormat = sizeFormat
    var suffixStr = ""
    
    //print("curUnitSize=\(curUnitSize), curSizeFormat=\(curSizeFormat)")
    
    if sizeInBytes < sizeKB {
        if curUnitSize == 0 {
            curUnitSize = sizeB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.0f"
        }
        
        suffixStr = " B"
    } else if (sizeInBytes >= sizeKB) && (sizeInBytes < sizeMB) {
        if curUnitSize == 0 {
            curUnitSize = sizeKB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " KB"
    } else if (sizeInBytes >= sizeMB) && (sizeInBytes < sizeGB) {
        if curUnitSize == 0 {
            curUnitSize = sizeMB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " MB"
    } else if (sizeInBytes >= sizeGB) && (sizeInBytes < sizeTB) {
        if curUnitSize == 0 {
            curUnitSize = sizeGB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " GB"
    } else if (sizeInBytes >= sizeTB) && (sizeInBytes < sizePB)  {
        if curUnitSize == 0 {
            curUnitSize = sizeTB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " TB"
    } else if sizeInBytes >= sizePB {
        if curUnitSize == 0 {
            curUnitSize = sizePB
        }
        
        if curSizeFormat.isEmpty {
            curSizeFormat = "%.2f"
        }
        
        suffixStr = " PB"
    }
    
    print("curUnitSize=\(curUnitSize), curSizeFormat=\(curSizeFormat)")
    
    let sizeFloat:Float = Float(sizeInBytes) / Float(curUnitSize)
    //print("sizeFloat=\(sizeFloat)")
    
    let sizeFloatStr = String(format: curSizeFormat, sizeFloat)
    //print("sizeFloatStr=\(sizeFloatStr)")
    
    sizeStr = sizeFloatStr + suffixStr
    
    print("sizeInBytes=\(sizeInBytes) -> sizeStr=\(sizeStr)")
    
    return sizeStr
}


/***************************************************************************
 * Number Related functions
 ***************************************************************************/

//get random int number within range: lower<=random<=upper
func getRandomInRange(_ lower:Int, upper:Int) -> Int {
    return lower + Int(arc4random_uniform(UInt32(upper - lower + 1)))
}

//get unique random int array number within range: lower<=random<=upper
func getUniqueRandomArrayInRange(_ lower:Int, upper:Int, arrCount:Int) -> [Int] {
    //print("lower=\(lower), upper=\(upper), arrCount=\(arrCount)")
    
    let singleRoundNum:Int = upper - lower + 1
    //print("singleRoundNum=\(singleRoundNum)")
    
    let invalidRandomNum = upper + 1
    //print("invalidRandomNum=\(invalidRandomNum)")
    //var uniqueRandomArr:[Int] = [Int](count: arrCount, repeatedValue: invalidRandomNum)
    var uniqueRandomArr:[Int] = [Int]()
    //print("uniqueRandomArr=\(uniqueRandomArr)")
    
    let remain = arrCount % singleRoundNum
    //print("remain=\(remain)")
    var maxRoundNum = arrCount / singleRoundNum
    if remain > 0 {
        maxRoundNum += 1
    }
    //print("maxRoundNum=\(maxRoundNum)")
    let maxRoundIdx = maxRoundNum - 1
    //print("maxRoundIdx=\(maxRoundIdx)")
    
    for roundIdx in 0...maxRoundIdx {
        //print("roundIdx=\(roundIdx)")
        
        var curRoundMaxNum:Int = 0
        if roundIdx < maxRoundIdx {
            curRoundMaxNum = singleRoundNum
        }
        else if roundIdx == maxRoundIdx {
            curRoundMaxNum = arrCount - roundIdx * singleRoundNum
        }
        //print("curRoundMaxNum=\(curRoundMaxNum)")
        
        let curRoundMaxIdx = curRoundMaxNum - 1
        //print("curRoundMaxIdx=\(curRoundMaxIdx)")
        
        var curRoundUniqueRandomArr:[Int] = [Int](repeating: invalidRandomNum, count: curRoundMaxNum)
        //print("curRoundUniqueRandomArr=\(curRoundUniqueRandomArr)")
        
        for idxWithinRound in 0...curRoundMaxIdx {
            //print("idxWithinRound=\(idxWithinRound)")
            var curRandomNum:Int
            
            repeat {
                curRandomNum = getRandomInRange(lower, upper: upper)
                //print("curRandomNum=\(curRandomNum)")
            }while(curRoundUniqueRandomArr.contains(curRandomNum))
            
            curRoundUniqueRandomArr[idxWithinRound] = curRandomNum
            //print("[\(idxWithinRound)] curRoundUniqueRandomArr=\(curRoundUniqueRandomArr)")
        }
        
        uniqueRandomArr += curRoundUniqueRandomArr
        //uniqueRandomArr.appendContentsOf(curRoundUniqueRandomArr)
        //print("uniqueRandomArr=\(uniqueRandomArr)")
    }
    
    return uniqueRandomArr
}
