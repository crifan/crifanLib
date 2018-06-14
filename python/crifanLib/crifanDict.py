#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanDict.py
Function: crifanLib's dict related functions.
Version: v1.0 20180614
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


import sys
import crifanLib.crifanSystem

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanDict"

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
#  Function
################################################################################


def recursiveMergeDict(originalDict, toMergeDict):
    """
    Recursively merge origin and to merge dict, return merged dict.
    Sub dict's won't be overwritten but also updated.
    """
    originalDictItems = None

    if crifanSystem.isPython2():
        originalDictItems = originalDict.iteritems()
    else:  # is python 3
        originalDictItems = originalDict.items()

    mergedDict = toMergeDict.copy()

    for key, value in originalDictItems:
        if key not in mergedDict:
            mergedDict[key] = value
        elif isinstance(value, dict):
            recursiveMergeDict(value, mergedDict[key])

    return mergedDict

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))