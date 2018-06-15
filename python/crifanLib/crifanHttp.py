#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanHttp.py
Function: crifanLib's http related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


import urllib
import zlib

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

# from . import crifanFile
import crifanLib.crifanFile

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanHttp"

################################################################################
# Global Variable
################################################################################
gVal = {

}

gConst = {
    'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)',
    # 'UserAgent' : "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Firefox/15.0.1",

    'defaultTimeout': 20,  # default timeout seconds for urllib2.urlopen
}

################################################################################
# Internal Function
################################################################################


################################################################################
# HTTP Function: Network related urllib/urllib2/http
################################################################################


def isFileValid(fileUrl):
    """
        check file validation:
        open file url to check return info is match or not
        with exception support
        note: should handle while the file url is redirect
        eg :
        http://publish.it168.com/2007/0627/images/500754.jpg ->
        http://img.publish.it168.com/2007/0627/images/500754.jpg
        other special one:
        sina pic url:
        http://s14.sinaimg.cn/middle/3d55a9b7g9522d474a84d&690
        http://s14.sinaimg.cn/orignal/3d55a9b7g9522d474a84d
        the real url is same with above url
    :param fileUrl:
    :return:
    """
    fileIsValid = False
    errReason = "Unknown error"

    try:
        # print "original fileUrl=",fileUrl
        origFileName = fileUrl.split('/')[-1]
        # print "origFileName=",origFileName

        # old: https://ie2zeq.bay.livefilestore.com/y1mo7UWr-TrmqbBhkw52I0ii__WE6l2UtMRSTZHSky66-uDxnCdKPr3bdqVrpUcQHcoJLedlFXa43bvCp_O0zEGF3JdG_yZ4wRT-c2AQmJ_TNcWvVZIXfBDgGerouWyx19WpA4I0XQR1syRJXjDNpwAbQ/IMG_5214_thumb[1].jpg
        # new: https://kxoqva.bay.livefilestore.com/y1mQlGjwNAYiHKoH5Aw6TMNhsCmX2YDR3vPKnP86snuqQEtnZgy3dHkwUvZ61Ah8zU3AGiS4whmm_ADrvxdufEAfMGo56KjLdhIbosn9F34olQ/IMG_5214_thumb%5b1%5d.jpg
        unquotedOrigFilenname = urllib.unquote(origFileName)
        # print "unquotedOrigFilenname=",unquotedOrigFilenname
        lowUnquotedOrigFilename = unquotedOrigFilenname.lower()
        # print "lowUnquotedOrigFilename=",lowUnquotedOrigFilename

        # resp = urllib2.urlopen(fileUrl, timeout=gConst['defaultTimeout']); # note: Python 2.6 has added timeout support.
        # some url, such as
        # http://my.csdn.net/uploads/201205/03/1336006009_2164.jpg
        # if not give user-agent, then will error: HTTP Error 403: Forbidden
        request = urllib2.Request(fileUrl, headers={'User-Agent': gConst['UserAgent']})
        # print "request=",request
        resp = urllib2.urlopen(request, timeout=gConst['defaultTimeout'])

        # print "resp=",resp
        realUrl = resp.geturl()
        # print "realUrl=",realUrl
        newFilename = realUrl.split('/')[-1]
        # print "newFilename=",newFilename

        # http://blog.sina.com.cn/s/blog_696e50390100ntxs.html
        unquotedNewFilename = urllib.unquote(newFilename)
        # print "unquotedNewFilename=",unquotedNewFilename
        unquotedLowNewFilename = unquotedNewFilename.lower()
        # print "unquotedLowNewFilename=",unquotedLowNewFilename

        respInfo = resp.info()
        # print "respInfo=",respInfo
        respCode = resp.getcode()
        # print "respCode=",respCode

        # special:
        # http://116.img.pp.sohu.com/images/blog/2007/5/24/17/24/11355bf42a9.jpg
        # return no content-length
        # contentLen = respInfo['Content-Length']

        # for redirect, if returned size>0 and filename is same, also should be considered valid
        # if (origFileName == newFilename) and (contentLen > 0):
        # for redirect, if returned response code is 200(OK) and filename is same, also should be considered valid
        # if (origFileName == newFilename) and (respCode == 200):
        if (lowUnquotedOrigFilename == unquotedLowNewFilename) and (respCode == 200):
            fileIsValid = True
        else:
            fileIsValid = False

            # eg: Content-Type= image/gif, ContentTypes : audio/mpeg
            # more ContentTypes can refer: http://kenya.bokee.com/3200033.html
            contentType = respInfo['Content-Type']

            #errReason = "file url returned info: type=%s, len=%d, realUrl=%s" % (contentType, contentLen, realUrl)
            errReason = "file url returned info: type=%s, realUrl=%s" % (contentType, realUrl)
    except urllib2.URLError as reason:
        fileIsValid = False
        errReason = reason
    except urllib2.HTTPError as code:
        fileIsValid = False
        errReason = code
    except:
        fileIsValid = False
        errReason = "Unknown error"

    # here type(errReason)= <class 'urllib2.HTTPError'>, so just convert it to str
    errReason = str(errReason)
    return (fileIsValid, errReason)


def downloadFile(fileUrl, fileToSave, needReport=False):
    """
        download from fileUrl then save to fileToSave
        with exception support
        note: the caller should make sure the fileUrl is a valid internet resource/file
    :param fileUrl:
    :param fileToSave:
    :param needReport:
    :return:
    """
    isDownOK = False
    downloadingFile = ''

    # note: totalFileSize -> may be -1 on older FTP servers which do not return a file size in response to a retrieval request
    def reportHook(copiedBlocks, blockSize, totalFileSize):
        # global downloadingFile
        if copiedBlocks == 0:  # 1st call : once on establishment of the network connection
            print('Begin to download %s, total size=%d' % (downloadingFile, totalFileSize))
        else:  # rest call : once after each block read thereafter
            print('Downloaded bytes: %d\r' % (blockSize * copiedBlocks),)
        return

    # ---------------------------------------------------------------------------
    try:
        if fileUrl:
            downloadingFile = fileUrl
            if needReport:
                urllib.urlretrieve(fileUrl, fileToSave, reportHook)
            else:
                urllib.urlretrieve(fileUrl, fileToSave)
            isDownOK = True
        else:
            print("Input download file url is NULL")
    except urllib.ContentTooShortError:
        isDownOK = False
    except:
        isDownOK = False

    return isDownOK


def manuallyDownloadFile(fileUrl, fileToSave, headerDict=""):
    """manually download fileUrl then save to fileToSave, with header support"""
    isDownOK = False
    errReason = "No error"

    try:
        if fileUrl:
            respHtml = ""
            if (headerDict):
                respHtml = getUrlRespHtml(fileUrl, headerDict=headerDict, useGzip=False,
                                          timeout=gConst['defaultTimeout'])
            else:
                # 1. find real address
                # print "fileUrl=",fileUrl
                resp = urllib2.urlopen(fileUrl, timeout=gConst['defaultTimeout'])
                # print "resp=",resp
                realUrl = resp.geturl()  # not same with original file url if redirect
                # if url is invalid, then add timeout can avoid dead
                respHtml = getUrlRespHtml(realUrl, useGzip=False, timeout=gConst['defaultTimeout'])

            if (respHtml):
                isDownOK = crifanLib.crifanFile.saveBinDataToFile(respHtml, fileToSave)
        else:
            print("Input download file url is NULL")
    except urllib2.URLError as reason:
        isDownOK = False
        errReason = reason
    except urllib2.HTTPError as code:
        isDownOK = False
        errReason = code
    except:
        isDownOK = False
        errReason = "Unknown error"

    # print "isDownOK=%s, errReason=%s"%(isDownOK, errReason)
    return isDownOK


def getUrlResponse(url, postDict={}, headerDict={}, timeout=0, useGzip=False, postDataDelimiter="&"):
    """Get response from url, support optional postDict,headerDict,timeout,useGzip

    Note:
    1. if postDict not null, url request auto become to POST instead of default GET
    2  if you want to auto handle cookies, should call initAutoHandleCookies() before use this function.
       then following urllib2.Request will auto handle cookies
    """

    # makesure url is string, not unicode, otherwise urllib2.urlopen will error
    url = str(url)

    if (postDict):
        if (postDataDelimiter == "&"):
            postData = urllib.urlencode(postDict)
        else:
            postData = ""
            for eachKey in postDict.keys():
                postData += str(eachKey) + "=" + str(postDict[eachKey]) + postDataDelimiter
        postData = postData.strip()
        # logging.info("postData=%s", postData)
        req = urllib2.Request(url, postData)
        # logging.info("req=%s", req)
        req.add_header('Content-Type', "application/x-www-form-urlencoded")
    else:
        req = urllib2.Request(url)

    defHeaderDict = {
        'User-Agent': gConst['UserAgent'],
        'Cache-Control': 'no-cache',
        'Accept': '*/*',
        'Connection': 'Keep-Alive',
    };

    # add default headers firstly
    for eachDefHd in defHeaderDict.keys():
        # print "add default header: %s=%s"%(eachDefHd,defHeaderDict[eachDefHd])
        req.add_header(eachDefHd, defHeaderDict[eachDefHd])

    if (useGzip):
        # print "use gzip for",url;
        req.add_header('Accept-Encoding', 'gzip, deflate')

    # add customized header later -> allow overwrite default header
    if (headerDict):
        # print "added header:",headerDict
        for key in headerDict.keys():
            req.add_header(key, headerDict[key])

    if (timeout > 0):
        # set timeout value if necessary
        resp = urllib2.urlopen(req, timeout=timeout)
    else:
        resp = urllib2.urlopen(req)

    # update cookies into local file
    if (gVal['cookieUseFile']):
        gVal['cj'].save()
        # logging.info("gVal['cj']=%s", gVal['cj'])

    return resp


def getUrlRespHtml(url, postDict={}, headerDict={}, timeout=0, useGzip=True, postDataDelimiter="&"):
    """
        get response html==body from url
        def getUrlRespHtml(url, postDict={}, headerDict={}, timeout=0, useGzip=False) :
    :param url:
    :param postDict:
    :param headerDict:
    :param timeout:
    :param useGzip:
    :param postDataDelimiter:
    :return:
    """
    resp = getUrlResponse(url, postDict, headerDict, timeout, useGzip, postDataDelimiter)
    respHtml = resp.read()

    # here, maybe, even if not send Accept-Encoding: gzip, deflate
    # but still response gzip or deflate, so directly do undecompress
    # if(useGzip) :

    # print "---before unzip, len(respHtml)=",len(respHtml);
    respInfo = resp.info()

    # Server: nginx/1.0.8
    # Date: Sun, 08 Apr 2012 12:30:35 GMT
    # Content-Type: text/html
    # Transfer-Encoding: chunked
    # Connection: close
    # Vary: Accept-Encoding
    # ...
    # Content-Encoding: gzip

    # sometime, the request use gzip,deflate, but actually returned is un-gzip html
    # -> response info not include above "Content-Encoding: gzip"
    # eg: http://blog.sina.com.cn/s/comment_730793bf010144j7_3.html
    # -> so here only decode when it is indeed is gziped data

    # Content-Encoding: deflate
    if ("Content-Encoding" in respInfo):
        if ("gzip" == respInfo['Content-Encoding']):
            respHtml = zlib.decompress(respHtml, 16 + zlib.MAX_WBITS)
        elif ("deflate" == respInfo['Content-Encoding']):
            respHtml = zlib.decompress(respHtml, -zlib.MAX_WBITS)

    return respHtml


def getUrlRespHtml_multiTry(url,
                            postDict={},
                            headerDict={},
                            timeout=0,
                            useGzip=True,
                            postDataDelimiter="&",
                            maxTryNum=5):
    """
        get url response html, multiple try version:
            if fail, then retry
    """
    respHtml = ""

    # access url
    # mutile retry, if some (mostly is network) error
    for tries in range(maxTryNum):
        try:
            respHtml = getUrlRespHtml(url, postDict, headerDict, timeout, useGzip, postDataDelimiter)
            # logging.debug("Successfully access url %s", url);
            break  # successfully, so break now
        except:
            if tries < (maxTryNum - 1):
                # logging.warning("Access url %s fail, do %d retry", url, (tries + 1))
                continue
            else:  # last try also failed, so exit
                # logging.error("Has tried %d times to access url %s, all failed!", maxTryNum, url)
                break

    return respHtml



################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))