#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanMath.py
Function: crifanLib's math related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import re
import math
import uuid
import random
import string

try:
    import md5
except ImportError:
    from hashlib import md5

################################################################################
# Config
################################################################################

RANDOM_MAX_DIGIT_LENGTH = 12

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanMath"

################################################################################
# Global Variable
################################################################################
gVal = {
}

gConst = {
}


# abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
gConst['DIGITS'] = string.digits
gConst['ASCII_LETTERS'] = string.ascii_letters
gConst['ALPHANUMERIC_LETTERS'] = gConst['ASCII_LETTERS'] + gConst['DIGITS']



################################################################################
# Internal Function
################################################################################


################################################################################
# Math Function
################################################################################

#----------------------------------------
# log==Logarithm
#----------------------------------------

def ConvertELogStrToValue(eLogStr):
    """
    convert string of natural logarithm base of E to value
    return (convertOK, convertedValue)
    eg:
    input:  -1.1694737e-003
    output: -0.0582246670563

    input:  8.9455025e-004
    output: 0.163843
    """

    (convertOK, convertedValue) = (False, 0.0)
    foundEPower = re.search("(?P<coefficientPart>-?\d+\.\d+)e(?P<ePowerPart>-\d+)", eLogStr, re.I)
    # print "foundEPower=",foundEPower
    if (foundEPower):
        coefficientPart = foundEPower.group("coefficientPart")
        ePowerPart = foundEPower.group("ePowerPart")
        # print "coefficientPart=%s,ePower=%s"%(coefficientPart, ePower)
        coefficientValue = float(coefficientPart)
        ePowerValue = float(ePowerPart)
        # print "coefficientValue=%f,ePowerValue=%f"%(coefficientValue, ePowerValue)
        # math.e= 2.71828182846
        wholeOrigValue = coefficientValue * math.pow(math.e, ePowerValue)
        # print "wholeOrigValue=",wholeOrigValue

        (convertOK, convertedValue) = (True, wholeOrigValue)
    else:
        (convertOK, convertedValue) = (False, 0.0)

    return convertOK, convertedValue



#----------------------------------------
# UUID
#----------------------------------------

def generateUUID(prefix = ""):
    generatedUuid4 = uuid.uuid4()
    generatedUuid4Str = str(generatedUuid4)
    newUuid = prefix + generatedUuid4Str
    return newUuid


#----------------------------------------
# MD5
#----------------------------------------


def generateMd5(strToMd5) :
    """
    generate md5 string from input string

    eg:
        xxxxxxxx -> af0230c7fcc75b34cbb268b9bf64da79

    :param strToMd5: input string
    :return: md5 string
    """

    encrptedMd5 = ""
    md5Instance = md5.new()
    # logging.debug("md5Instance=%s", md5Instance)
    #md5Instance=<md5 HASH object @ 0x1062af738>
    md5Instance.update(strToMd5)
    # logging.debug("md5Instance=%s", md5Instance)
    #md5Instance=<md5 HASH object @ 0x1062af738>
    encrptedMd5 = md5Instance.hexdigest()
    # logging.debug("encrptedMd5=%s", encrptedMd5)
    #encrptedMd5=af0230c7fcc75b34cbb268b9bf64da79

    return encrptedMd5

#----------------------------------------
# Random String/Number
#----------------------------------------


def genRandomStr(choiceStr, length):
    """random number and string"""
    randomStr = ''.join([random.choice(choiceStr) for _ in range(length)])
    return randomStr


def genRandomDigit(length):
    randomDigits = genRandomStr(gConst['DIGITS'], length=length)
    return randomDigits


def genRandomAlphanum(length):
    randomAlphanum = genRandomStr(gConst['ALPHANUMERIC_LETTERS'], length=length)
    return randomAlphanum


def randDigitsStr(digitNum=RANDOM_MAX_DIGIT_LENGTH):
    """
    generated the random digits number string within designated max length
    :param digitNum:
    :return:
    """
    if (digitNum > RANDOM_MAX_DIGIT_LENGTH):
        digitNum = 12

    randVal = random.random()
    # print "randVal=",randVal #randVal= 0.134248340235
    randVal = str(randVal)
    # print "randVal=",randVal #randVal= 0.134248340235

    randVal = randVal.replace("0.", "")
    # print "randVal=",randVal #randVal= 0.134248340235

    # if last is 0, append that 0
    if len(randVal) == (RANDOM_MAX_DIGIT_LENGTH-1):
        randVal = randVal + "0"
    # print "randVal=",randVal #randVal= 0.134248340235

    # randVal = randVal.replace("e+11", "")
    # randVal = randVal.replace(".", "")
    # print "randVal=",randVal #randVal= 0.134248340235
    randVal = randVal[0: digitNum]
    # print "randVal=",randVal #randVal= 0.134248340235

    return randVal

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))