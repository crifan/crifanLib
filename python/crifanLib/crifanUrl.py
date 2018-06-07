#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanUrl.py
Function: crifanLib's url related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanUrl"

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
# URL Function
################################################################################


################################################################################
# URL
################################################################################


def genFullUrl(mainUrl, paraDict):
    """
    generate the full url, which include the main url plus the parameter list
    Note:
        normally just use urllib.urlencode is OK.
        only use this if you do NOT want urllib.urlencode convert some special chars($,:,{,},...) into %XX
    :param mainUrl:
    :param paraDict:
    :return:
    """
    fullUrl = mainUrl
    fullUrl += '?'
    for i, para in enumerate(paraDict.keys()):
        if(i == 0):
            # first para no '&'
            fullUrl += str(para) + '=' + str(paraDict[para])
        else:
            fullUrl += '&' + str(para) + '=' + str(paraDict[para])
    return fullUrl


def urlIsSimilar(url1, url2):
    """
    check whether two url is similar
        Note: input two url both should be str type
    """
    isSim = False

    url1 = str(url1)
    url2 = str(url2)

    slashList1 = url1.split('/')
    slashList2 = url2.split('/')
    lenS1 = len(slashList1)
    lenS2 = len(slashList2)

    # all should have same structure
    if lenS1 != lenS2:
        # not same sturcture -> must not similar
        isSim = False
    else:
        sufPos1 = url1.rfind('.')
        sufPos2 = url2.rfind('.')
        suf1 = url1[(sufPos1 + 1) : ]
        suf2 = url2[(sufPos2 + 1) : ]
        # at least, suffix should same
        if (suf1 == suf2):
            lastSlashPos1 = url1.rfind('/')
            lastSlashPos2 = url2.rfind('/')
            exceptName1 = url1[:lastSlashPos1]
            exceptName2 = url2[:lastSlashPos2]
            # except name, all other part should same
            if (exceptName1 == exceptName2):
                isSim = True
            else :
                # except name, other part is not same -> not similar
                isSim = False
        else:
            # suffix not same -> must not similar
            isSim = False

    return isSim

def findSimilarUrl(url, urlList):
    """
        found whether the url is similar in urlList
        if found, return True, similarSrcUrl
        if not found, return False, ''
    :param url:
    :param urlList:
    :return:
    """
    (isSimilar, similarSrcUrl) = (False, '')
    for srcUrl in urlList:
        if urlIsSimilar(url, srcUrl):
            isSimilar = True
            similarSrcUrl = srcUrl
            break
    return (isSimilar, similarSrcUrl)

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))