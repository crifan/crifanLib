#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanFile.py
Function: crifanLib's file related functions.
Last Update: 20181122
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import os
import sys
import shutil
import codecs
import pysrt
import chardet

# from . import crifanList
import crifanLib.crifanList

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanFile"

################################################################################
# Global Variable
################################################################################
gVal = {
    'picSufChars': '',  # store the pic suffix char list
}

gConst = {
    # also belong to ContentTypes, more info can refer: http://kenya.bokee.com/3200033.html
    # here use Tuple to avoid unexpected change
    # note: for tuple, refer item use tuple[i], not tuple(i)
    'picSufList': ('bmp', 'gif', 'jpeg', 'jpg', 'jpe', 'png', 'tiff', 'tif'),
}

################################################################################
# Internal Function
################################################################################


def genSufList():
    """generate the suffix char list according to constant picSufList"""
    global gConst

    sufChrList = []
    for suffix in gConst['picSufList']:
        for c in suffix:
            sufChrList.append(c)

    sufChrList = crifanLib.crifanList.uniqueList(sufChrList)
    # sufChrList = uniqueList(sufChrList)
    sufChrList.sort()
    joinedSuf = ''.join(sufChrList)
    swappedSuf = joinedSuf.swapcase()
    wholeSuf = joinedSuf + swappedSuf

    return wholeSuf

################################################################################
# File Function
################################################################################

def saveBinDataToFile(binaryData, fileToSave):
    """save binary data into file"""
    saveOK = False
    try:
        # open a file, if not exist, create it
        savedBinFile = open(fileToSave, "wb")
        #print "savedBinFile=",savedBinFile
        savedBinFile.write(binaryData)
        savedBinFile.close()
        saveOK = True
    except :
        saveOK = False
    return saveOK


def saveDataToFile(fullFilename, binaryData):
    """save binary data info file"""
    with open(fullFilename, 'wb') as fp:
        fp.write(binaryData)
        fp.close()
        # logging.debug("Complete save file %s", fullFilename)

def saveJsonToFile(fullFilename, jsonValue):
    """save json dict into file"""
    with codecs.open(fullFilename, 'w', encoding="utf-8") as jsonFp:
        json.dump(jsonValue, jsonFp, indent=2, ensure_ascii=False)
        logging.debug("Complete save json %s", fullFilename)

def loadJsonFromFile(fullFilename):
    """load and parse json dict from file"""
    with codecs.open(fullFilename, 'r', encoding="utf-8") as jsonFp:
        jsonDict = json.load(jsonFp)
        logging.debug("Complete load json from %s", fullFilename)
        return jsonDict

def loadTextFromFile(fullFilename):
    """load file text content from file"""
    with codecs.open(fullFilename, 'r', encoding="utf-8") as fp:
        allText = fp.read()
        logging.debug("Complete load text from %s", fullFilename)
        return allText

################################################################################
# Folder Function
################################################################################

def deleteFolder(folderFullPath):
    """
        delete folder
        Note:makesure folder is already existed
    """
    if os.path.exists(folderFullPath):
        shutil.rmtree(folderFullPath)

def createFolder(folderFullPath):
    """
        create folder, even if already existed
        Note: for Python 3.2+
    """
    os.makedirs(folderFullPath, exist_ok=True)


################################################################################
# Filename Function
################################################################################

def getPicSufList():
    """get supported picture suffix list"""
    return gConst['picSufList']


def getPicSufChars():
    """get supported picture suffix chars"""
    if not gVal['picSufChars']:
        gVal['picSufChars'] = genSufList()

    return gVal['picSufChars']


def getBasename(fullFilename):
    """
    get base filename

    Examples:
        xxx.exe          -> xxx.exe
        xxx              -> xxx
        Mac/Linux:
           your/path/xxx.py -> xxx.py
        Windows:
           your\path\\xxx.py -> xxx.py
    """

    return os.path.basename(fullFilename)


def getFileSuffix(filename):
    """
        get file suffix from file name
        no dot/period, no space/newline, makesure lower case

        "xxx.mp3" -> "mp3"
        "xxx.pdf" -> "pdf"
        "xxx.mp3 " -> "mp3"
        "xxx.JPg" -> "jpg"

    :param filename:
    :return:
    """
    fileSuffix = ""

    if filename:
        name, extension = os.path.splitext(filename)
        fileSuffix = extension # .mp3

    if fileSuffix:
        # remove leading dot/period
        fileSuffix = fileSuffix[1:] # mp3

    if fileSuffix:
        # remove ending newline or space
        fileSuffix = fileSuffix.strip()

    if fileSuffix:
        # convert JPg to jpg
        fileSuffix = fileSuffix.lower()

    return fileSuffix


def removeSuffix(fileBasename):
    """
    remove file suffix

    Examples:
        xxx.exe -> xxx
        xxx -> xxx
    """

    splitedTextArr = os.path.splitext(fileBasename)
    filenameRemovedSuffix = splitedTextArr[0]
    return filenameRemovedSuffix


def getInputFilename():
    """
    get input filename, from argv

    Examples:
        AutoOrder.py -> AutoOrder.py
        python AutoOrder.py -> AutoOrder.py
        python AutoOrder/AutoOrder.py -> AutoOrder/AutoOrder.py
    """

    argvList = sys.argv
    # print "argvList=%s"%(argvList)
    return argvList[0]


def getInputFileBasename(inputFilename = None):
    """
    get input file's base name

    Examples:
        AutoOrder.py -> AutoOrder.py
        AutoOrder/AutoOrder.py -> AutoOrder.py
    """

    curInputFilename = getInputFilename()

    if inputFilename :
        curInputFilename = inputFilename

    # print "curInputFilename=%s"%(curInputFilename)
    inputBasename = getBasename(curInputFilename)
    # print "inputBasename=%s"%(inputBasename)
    return inputBasename


def getInputFileBasenameNoSuffix():
    """
    get input file base name without suffix

    Examples:
        AutoOrder.py -> AutoOrder
        AutoOrder/AutoOrder.py -> AutoOrder
    """

    inputFileBasename = getInputFileBasename()
    basenameRemovedSuffix = removeSuffix(inputFileBasename)
    return basenameRemovedSuffix

################################################################################
# SRT Subtitle Parsing
################################################################################

def extractRawSubtitleList(subtitleFullPath, srtEncodingConfidenceThreshold = 0.8, defaultEncoding="utf-8"):
    """
        extract subtitle text file to raw subtitle list of dict {start, end, text},
        and support auto detect srt file encoding
    """

    getSubOk = False
    rawSubtitleListOrErrMsg = "Unknown Error"

    with open(subtitleFullPath, 'rb') as subtitleFp:
        fileContentStr = subtitleFp.read()
        detectedResult = chardet.detect(fileContentStr)
        # logging.debug("detectedResult=%s", detectedResult)
        fileEncoding = defaultEncoding
        if detectedResult["confidence"] >= srtEncodingConfidenceThreshold:
            fileEncoding = detectedResult["encoding"] # 'UTF-8-SIG'
        # logging.debug("fileEncoding=%s", fileEncoding)

        try:
            rawSubtitleList = pysrt.open(subtitleFullPath, encoding=fileEncoding)
            rawSubtitleListOrErrMsg = rawSubtitleList
            getSubOk = True
        except Exception as openSrtException:
            rawSubtitleListOrErrMsg = str(openSrtException)
            # logging.debug("Error %s of pysrt.open %s", rawSubtitleListOrErrMsg, subtitleFullPath)

    return getSubOk, rawSubtitleListOrErrMsg


################################################################################
# Test
################################################################################


def testFile():
    filenameNoSuffix = getInputFileBasenameNoSuffix()
    print("filenameNoSuffix=%s" % filenameNoSuffix) #filenameNoSuffix=crifanFile


if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))

    testFile()