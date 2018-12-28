#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanWechat.py
Function: crifanLib's Wechat related functions.
Version: v20181224
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v20181224"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import base64
import json
from Crypto.Cipher import AES


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanWechat"

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

class WXBizDataCrypt:
    def __init__(self, appId, sessionKey):
        self.appId = appId
        self.sessionKey = sessionKey

    def decrypt(self, encryptedData, iv):
        # base64 decode
        sessionKey = base64.b64decode(self.sessionKey)
        encryptedData = base64.b64decode(encryptedData)
        iv = base64.b64decode(iv)

        cipher = AES.new(sessionKey, AES.MODE_CBC, iv)

        decriptedData = cipher.decrypt(encryptedData)

        unpadedData = self._unpad(decriptedData)

        decrypted = json.loads(unpadedData)

        if decrypted['watermark']['appid'] != self.appId:
            raise Exception('Invalid Buffer')

        return decrypted

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


################################################################################
# Wechat Function
################################################################################

def decryptWechatInfo(appId, sessionKey, encryptedData, iv):
    """
        decrypt wechat info, return from https://developers.weixin.qq.com/miniprogram/dev/api/wx.getUserInfo.html
    """
    cryptObj = WXBizDataCrypt(appId, sessionKey)
    decryptedInfo = cryptObj.decrypt(encryptedData, iv)
    return decryptedInfo


################################################################################
# Test
################################################################################

def testdecryptWechatInfo():
    appId = 'wx1e89041e13bdd7b0'
    sessionKey = 'lcYPydQya+PZiXcCTYL6FA=='
    encryptedData = "x62TeNl4hBvBIl1WW81KClApM7iAoedv1d8cd0apaGwuggbEHXOt+Xaj8gOyr8yqtFlAQfbOIgaZcPxR+D5w9YfUHJ4gqXb8kSajx9ylMyQZU/TRQIEuVXhlqjjJwPj+Dil4YBpOCCTKQmJ4ZT4HlwfkTFkgMz86ldPTb1CHzetNVB9NK0gLKEOCJBNQgiX3u7My6r7Grj3P28ExgqDD4TDGlx1x9rSv41gBL1mPoptgUQXi67Q7n6NO8Z17V3ED9sFLWpUhVOnmRg1Y+0WldxpyXrUdtO2vyqWrB3I8knllzh1vJUUrinjBape8YnQyZKoif/eMw0EgW61opC9BNZWofLeP9SgAB+YlE8AqH7yJBBpNMElrqR2gpDisSzypFYkVPqnNxDEEoUJlpG3kOKozXyDXZE61BFcYifN8pp/FpYRbaS50EyWAk8AriKsIawAEpSfJpqU9gjI2GUUvyEGJRLMMcmw7eiO5jEag9ws="
    iv = "eTy4gl9plMLDjJuvKU3CMQ=="

    decryptedInfo = decryptWechatInfo(appId, sessionKey, encryptedData, iv)
    print("decryptedInfo=%s" % decryptedInfo)
    # {'openId': 'o7yT-4_njpDpgiMGYT4PLpW2j2BY', 'nickName': '小风尘', 'gender': 0, 'language': 'zh_CN', 'city': 'Suzhou', 'province': 'Jiangsu', 'country': 'China', 'avatarUrl': 'https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIDnEfia142B3RuK0unfk8vLa8vALSC2rwKicF3iaJrnxfibYKdMfeH1RhfbOrsl19OQbEMF10a8oIy5Q/132', 'watermark': {'timestamp': 1545986568, 'appid': 'wx1e89041e13bdd7b0'}}

if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))
    # testdecryptWechatInfo()