#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanSystem.py
Function: crifanLib's python system related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import sys
import subprocess

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


def runCommand(consoleCommand):
    """run command using subprocess call"""
    isRunCmdOk = False
    errMsg = "Unknown Error"

    try:
        resultCode = subprocess.check_call(consoleCommand, shell=True)
        if resultCode == 0:
            isRunCmdOk = True
            errMsg = ""
        else:
            isRunCmdOk = False
            errMsg = "%s return code %s" % (consoleCommand, resultCode)
    except subprocess.CalledProcessError as callProcessErr:
        isRunCmdOk = False
        errMsg = str(callProcessErr)
        # "Command 'ffmpeg -y -i /Users/crifan/.../debug/extractAudio/show_112233_video.mp4 -ss 00:00:05.359 -to 00:00:06.763 -b:a 128k /.../show_112233_video_000005359_000006763.mp3 2> /dev/null' returned non-zero exit status 1."

    return isRunCmdOk, errMsg

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))