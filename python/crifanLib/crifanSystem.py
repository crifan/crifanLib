#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanSystem.py
Function: crifanLib's python system related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import sys

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanSystem"

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
# Python System Function
################################################################################


def isPython2():
    """check whether is python 2"""
    return sys.version_info[0] == 2

def isPython3():
    """check whether is python 3"""
    return sys.version_info[0] == 3

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))