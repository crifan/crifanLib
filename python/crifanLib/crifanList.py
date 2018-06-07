#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanList.py
Function: crifanLib's list related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


# from . import crifanString
import crifanLib.crifanString


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanList"

################################################################################
# Global Variable
################################################################################
gVal = {
}

gConst = {
}

################################################################################
# Internal Function
################################################################################


################################################################################
# List Function
################################################################################


################################################################################
# List
################################################################################


def uniqueList(old_list):
    """remove overlapped item in the list"""
    newList = []
    for x in old_list:
        if x not in newList:
            newList.append(x)
    return newList

def genListStr(listValue, encForUniVal="UTF-8", isRetainLastComma=False, delimiter=","):
    """
    generate string of values in list, separated by delimiter
    eg:
    input: ["20121202", "天平山赏红枫", "动物"]
    output: 20121202,天平山赏红枫,动物
    """
    # print "listValue=",listValue;

    generatedListStr = ""
    for eachValue in listValue:
        if crifanString.isStringInstance(eachValue):
            generatedListStr += eachValue.encode(encForUniVal) + delimiter
        else:
            generatedListStr += str(eachValue) + delimiter

    if (not isRetainLastComma):
        if (generatedListStr and (generatedListStr[-1] == delimiter)):
            # remove last ,
            generatedListStr = generatedListStr[:-1]
    return generatedListStr


def removeEmptyInList(list):
    """remove the empty ones in list"""
    newList = []
    for val in list:
        if val:
            newList.append(val)
    return newList


def filterList(listToFilter, listToCompare):
    """
        for listToFilter, remove the ones which is in listToCompare,
        also return the ones which is already exist in listToCompare
    :param listToFilter:
    :param listToCompare:
    :return:
    """
    filteredList = []
    existedList = []
    for singleOne in listToFilter:  # remove processed
        if (not (singleOne in listToCompare)):
            # omit the ones in listToCompare
            filteredList.append(singleOne)
        else:
            # record the already exist ones
            existedList.append(singleOne)
    return (filteredList, existedList)


def tupleListToDict(tupleList):
    """
        convert tuple list to dict value
        [(u'type', u'text/javascript'), (u'src', u'http://partner.googleadservices.com/gampad/google_service.js')]
        { u'type':u'text/javascript', u'src':u'http://partner.googleadservices.com/gampad/google_service.js' }
    :param tupleList:
    :return:
    """
    convertedDict = {}
    for eachTuple in tupleList:
        (key, value) = eachTuple
        convertedDict[key] = value
    return convertedDict

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))