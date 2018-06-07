#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanCookie.py
Function: crifanLib's cookie related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


try:
    from http.cookiejar import CookieJar
    import urllib.request as urllib2
except ImportError:
    import urllib2
    import cookielib


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanCookie"

################################################################################
# Global Variable
################################################################################
gVal = {
    'cj': None,  # used to store current cookiejar, to support auto handle cookies
    'cookieUseFile': False
}

gConst = {
}

################################################################################
# Internal Function
################################################################################


################################################################################
# Cookie Function
################################################################################


def initAutoHandleCookies(localCookieFileName=None):
    """Add cookiejar to support auto handle cookies.
    support designate cookie file

    Note:
    after this init, later urllib2.urlopen will automatically handle cookies
    """

    if (localCookieFileName):
        gVal['cookieUseFile'] = True
        # print "use cookie file"

        # gVal['cj'] = cookielib.FileCookieJar(localCookieFileName); #NotImplementedError
        gVal['cj'] = cookielib.LWPCookieJar(localCookieFileName)  # prefer use this
        # gVal['cj'] = cookielib.MozillaCookieJar(localCookieFileName) # second consideration
        # create cookie file
        gVal['cj'].save()
    else:
        # print "not use cookie file"
        gVal['cookieUseFile'] = False

        gVal['cj'] = CookieJar()

    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(gVal['cj']))
    urllib2.install_opener(opener)

    # print "Auto handle cookies inited OK"
    return


def initProxy(singleProxyDict={}):
    """Add proxy support for later urllib2 auto use this proxy

    Note:
    1. tmp not support username and password
    2. after this init, later urllib2.urlopen will automatically use this proxy
    """

    proxyHandler = urllib2.ProxyHandler(singleProxyDict)
    # print "proxyHandler=",proxyHandler
    proxyOpener = urllib2.build_opener(proxyHandler)
    # print "proxyOpener=",proxyOpener
    urllib2.install_opener(proxyOpener)

    return


def initProxyAndCookie(singleProxyDict={}, localCookieFileName=None):
    """Init proxy and cookie

    Note:
    1. after this init, later urllib2.urlopen will auto, use proxy, auto handle cookies
    2. for proxy, tmp not support username and password
    """

    proxyHandler = urllib2.ProxyHandler(singleProxyDict)
    # print "proxyHandler=",proxyHandler

    if (localCookieFileName):
        gVal['cookieUseFile'] = True
        # print "use cookie file"

        # gVal['cj'] = cookielib.FileCookieJar(localCookieFileName) #NotImplementedError
        gVal['cj'] = cookielib.LWPCookieJar(localCookieFileName)  # prefer use this
        # gVal['cj'] = cookielib.MozillaCookieJar(localCookieFileName) # second consideration
        # create cookie file
        gVal['cj'].save()
    else:
        # print "not use cookie file"
        gVal['cookieUseFile'] = False

        gVal['cj'] = CookieJar()

    proxyAndCookieOpener = urllib2.build_opener(urllib2.HTTPCookieProcessor(gVal['cj']), proxyHandler)
    # print "proxyAndCookieOpener=",proxyAndCookieOpener
    urllib2.install_opener(proxyAndCookieOpener)

    return


def getCurrentCookies():
    """Return current cookies.

    Note:
    only call this this function, if you previously called initAutoHandleCookies
    """
    return gVal['cj']


def printCurrentCookies():
    """
        Just print current cookies for debug simplicity
    """
    if (gVal['cj']):
        for index, cookie in enumerate(gVal['cj']):
            print("[%d] name=%s,value=%s,domain=%s,path=%s,secure=%s,expires=%s,version=%d" %
                  (index, cookie.name, cookie.value, cookie.domain,
                   cookie.path, cookie.secure, cookie.expires, cookie.version))


def checkAllCookiesExist(cookieNameList, cookieJar):
    """Check all cookies('s name) in cookiesDict is exist in cookieJar or not"""
    cookiesDict = {}
    for eachCookieName in cookieNameList:
        cookiesDict[eachCookieName] = False

    allCookieFound = True
    for cookie in cookieJar:
        if (cookie.name in cookiesDict):
            cookiesDict[cookie.name] = True

    for eachCookie in cookiesDict.keys():
        if (not cookiesDict[eachCookie]):
            allCookieFound = False
            break

    return allCookieFound

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))