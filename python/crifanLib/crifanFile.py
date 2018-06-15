#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanFile.py
Function: crifanLib's file related functions.
Version: v1.0 20180605
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
# Test
################################################################################


def testFile():
    filenameNoSuffix = getInputFileBasenameNoSuffix()
    print("filenameNoSuffix=%s" % filenameNoSuffix) #filenameNoSuffix=crifanFile


if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))

    testFile()