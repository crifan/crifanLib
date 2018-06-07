#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanDatetime.py
Function: crifanLib's datetime related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


from datetime import datetime,timedelta
import time


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanDatetime"

################################################################################
# Global Variable
################################################################################
gVal = {
    'calTimeKeyDict': {}
}

gConst = {
}

################################################################################
# Internal Function
################################################################################


################################################################################
# Datetime Function
################################################################################


def convertLocalToGmt(localTime):
    """
        convert local GMT8 to GMT time
        Note: input should be 'datetime' type, not 'time' type
    :param localTime:
    :return:
    """
    return localTime - timedelta(hours=8)


def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string

    eg:
        20171111_220722

    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    return curDatetimeStr


def getCurTimestamp():
    """
    get current time's timestamp
        eg: 1351670162
    """
    return datetimeToTimestamp(datetime.now())


def datetimeToTimestamp(datetimeVal) :
    """
        convert datetime value to timestamp
        eg:
            "2006-06-01 00:00:00" -> 1149091200
    :param datetimeVal:
    :return:
    """
    return int(time.mktime(datetimeVal.timetuple()))


def timestampToDatetime(timestamp):
    """
        convert timestamp to datetime value
        eg:
            1149091200 -> "2006-06-01 00:00:00"
    :param timestamp:
    :return:
    """
    #print "type(timestamp)=",type(timestamp)
    #print "timestamp=",timestamp
    #timestamp = int(timestamp)
    timestamp = float(timestamp)
    return datetime.fromtimestamp(timestamp)


def calcTimeStart(uniqueKey):
    """init for calculate elapsed time"""
    global gVal

    gVal['calTimeKeyDict'][uniqueKey] = time.time()
    return


def calcTimeEnd(uniqueKey):
    """
        to get elapsed time
        Note: before call this, should use calcTimeStart to init
    :param uniqueKey:
    :return:
    """
    global gVal

    return time.time() - gVal['calTimeKeyDict'][uniqueKey]


################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))