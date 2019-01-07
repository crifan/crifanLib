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

import re

from crifanFile import loadTextFromFile


testInputFile = "python/crifanLib/demo/mac_show_control_char.txt"

def testDetectCtrlChar():
  fileText = loadTextFromFile(testInputFile)
  print("fileText=%s" % fileText)

  # controlCharList = re.findall('[^\x00-\x7F^\\u4e00-\\u9fa5]', fileText)
  controlCharList = re.findall('[^\x00-\x7F^\\u2E80-\\uFE4F^\\uFF00-\\uFFEF]', fileText)
  print("controlCharList=%s" % controlCharList)

  # for eachChar in fileText:

if __name__ == "__main__":
  testDetectCtrlChar()
