#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanDatetime.py
Function: crifanLib's datetime related functions.
Version: v1.1 20180713
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.1"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


from datetime import datetime,timedelta
from datetime import time  as datetimeTime
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


def getCurTimestamp(withMilliseconds=False):
    """
    get current time's timestamp
        (default)not milliseconds -> 10 digits: 1351670162
        with milliseconds -> 13 digits: 1531464292921
    """
    curDatetime = datetime.now()
    return datetimeToTimestamp(curDatetime, withMilliseconds)


def datetimeToTimestamp(datetimeVal, withMilliseconds=False) :
    """
        convert datetime value to timestamp
        eg:
            "2006-06-01 00:00:00.123" -> 1149091200
            if with milliseconds -> 1149091200123
    :param datetimeVal:
    :return:
    """
    timetupleValue = datetimeVal.timetuple()
    timestampFloat = time.mktime(timetupleValue) # 1531468736.0 -> 10 digits
    timestamp10DigitInt = int(timestampFloat) # 1531468736
    timestampInt = timestamp10DigitInt

    if withMilliseconds:
        microsecondInt = datetimeVal.microsecond # 817762
        microsecondFloat = float(microsecondInt)/float(1000000) # 0.817762
        timestampFloat = timestampFloat + microsecondFloat # 1531468736.817762
        timestampFloat = timestampFloat * 1000 # 1531468736817.7621 -> 13 digits
        timestamp13DigitInt = int(timestampFloat) # 1531468736817
        timestampInt = timestamp13DigitInt

    return timestampInt


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


def floatSecondsToDatetimeTime(floatSeconds):
    """
        convert float seconds(time delta) to datetime.time

        example: 27.83879017829895 -> datetime.time(0, 0, 27, 838790)

        Note: the max hour can NOT excedd 24 hors, otherwise will error: ValueError: hour must be in 0..23
    """
    secondsInt = int(floatSeconds)
    decimalsFloat = floatSeconds - secondsInt
    millisecondsFloat = decimalsFloat * 1000
    millisecondsInt = int(millisecondsFloat)
    microsecondsDecimal = millisecondsFloat - millisecondsInt
    microsecondsInt = int(microsecondsDecimal * 1000)

    minutes, seconds = divmod(secondsInt, 60)
    hours, minutes = divmod(minutes, 60)

    # datetimeTimeValue = datetime.time(
    datetimeTimeValue = datetimeTime(
        hour        =hours,
        minute      =minutes,
        second      =seconds,
        microsecond =(millisecondsInt * 1000) + microsecondsInt
    )

    return datetimeTimeValue


def floatSecondsToDatetimeDict(floatSeconds):
    """
        convert float seconds(time delta) to datetime dict{days, hours, minutes, seconds, millseconds, microseconds}

        example: 96400.3765293 -> {'days': 1, 'hours': 2, 'minutes': 46, 'seconds': 40, 'millseconds': 376, 'microseconds': 529}
    """
    secondsInt = int(floatSeconds)
    decimalsFloat = floatSeconds - secondsInt
    millisecondsFloat = decimalsFloat * 1000
    millisecondsInt = int(millisecondsFloat)
    microsecondsDecimal = millisecondsFloat - millisecondsInt
    microsecondsInt = int(microsecondsDecimal * 1000)

    minutes, seconds = divmod(secondsInt, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    convertedDict = {
        "days": days,
        "hours": hours,
        "minutes": minutes,
        "seconds": seconds,
        "millseconds": millisecondsInt,
        "microseconds": microsecondsInt,
    }

    return convertedDict


def datetimeDictToStr(datetimeDict, seperatorD=" ", seperatorHms=":", seperatorMilliS="."):
    formattedStr = "%d%s%02d%s%02d%s%02d%s%03d" % (
        datetimeDict["days"], seperatorD,
        datetimeDict["hours"], seperatorHms,
        datetimeDict["minutes"], seperatorHms,
        datetimeDict["seconds"], seperatorMilliS,
        datetimeDict["millseconds"])
    return formattedStr

################################################################################
# Test
################################################################################

def testTimestamp():
    # test timestamp with milliseconds
    timestampNoMilliSec = getCurTimestamp()
    print("timestampNoMilliSec=%s" % timestampNoMilliSec) # 1531468833
    timestampWithMilliSec = getCurTimestamp(withMilliseconds=True)
    print("timestampWithMilliSec=%s" % timestampWithMilliSec) # 1531468833344

if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))

    # testTimestamp()
