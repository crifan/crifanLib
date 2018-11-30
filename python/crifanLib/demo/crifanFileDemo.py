import sys
import os
curFolder = os.path.abspath(__file__)
parentFolder = os.path.dirname(curFolder)
parentParentFolder = os.path.dirname(parentFolder)
parentParentParentFolder = os.path.dirname(parentParentFolder)
sys.path.append(curFolder)
sys.path.append(parentFolder)
sys.path.append(parentParentFolder)
sys.path.append(parentParentParentFolder)

from crifanFile import getFileFolderSize, formatSize

def testNormalFile():
  normalFile = "/Users/crifan/dev/dev_root/crifan/CrifanLib/crifanLib/python/crifanLib/demo/crifanFileDemo.py"
  normalFileSize = getFileFolderSize(normalFile)
  print("normalFileSize=%s" % normalFileSize) # 956

def testFoler():
  userFolder = "/Users/crifan/dev/dev_root/crifan/CrifanLib/crifanLib/python"
  userFolderSize = getFileFolderSize(userFolder)
  print("userFolderSize=%s" % userFolderSize) # 295982

def demoGetFileFolderSize():
  testNormalFile()
  testFoler()




def testKb():
  kbSize = 3746
  kbStr = formatSize(kbSize)
  print("%s -> %s" % (kbSize, kbStr))

def testI():
  iSize = 87533
  iStr = formatSize(iSize, isUnitWithI=True)
  print("%s -> %s" % (iSize, iStr))

def testBytes():
  bytesSize = 352
  bytesStr = formatSize(bytesSize)
  print("%s -> %s" % (bytesSize, bytesStr))

def testMb():
  mbSize = 76383285
  mbStr = formatSize(mbSize, decimalNum=2)
  print("%s -> %s" % (mbSize, mbStr))

def testTb():
  tbSize = 763832854988542
  tbStr = formatSize(tbSize, decimalNum=2)
  print("%s -> %s" % (tbSize, tbStr))

def testPb():
  pbSize = 763832854988542665
  pbStr = formatSize(pbSize, decimalNum=4)
  print("%s -> %s" % (pbSize, pbStr))


def demoFormatSize():
  testKb()
  testI()
  testBytes()
  testMb()
  testTb()
  testPb()

if __name__ == "__main__":
  demoGetFileFolderSize()
  demoFormatSize()

  """
  normalFileSize=1759
  userFolderSize=296785
  3746 -> 3.7KB
  87533 -> 85.5KiB
  352 -> 352.0B
  76383285 -> 72.84MB
  763832854988542 -> 694.70TB
  763832854988542665 -> 678.4199PB
  """