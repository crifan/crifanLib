#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanString.py
Function: crifanLib's string related functions.
Version: v1.2 20180615
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.2"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


import re
import json
import random

try:
    import chardet
except ImportError:
    print("crifanString: Can not found lib chardet")

import urllib

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

import codecs

# from . import crifanMath
# from . import crifanHttp
# from . import crifanSystem
import crifanLib.crifanMath
import crifanLib.crifanHttp
import crifanLib.crifanSystem

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanString"

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
# String Function
################################################################################


################################################################################
# String
################################################################################



def strToList(inputStr, separatorChar=","):
    """
        convert string to list by using separator char, and strip each str in list

        example:
            u'Family members,  Sick'
            or 'Family members,  Sick,'
            ->
            [u'Family members', u'Sick']
    :param separatorChar: the separator char
    :return: converted list
    """
    convertedList = []
    stripedList = []

    if inputStr:
        convertedList = inputStr.split(separatorChar) #<type 'list'>: [u'Family members', u'Sick']

        for eachStr in convertedList:
            stripedStr = eachStr.strip()
            if stripedStr:
                stripedList.append(stripedStr)

    return stripedList


def isStringInstance(someVar):
    """check whether is string instance"""
    if crifanLib.crifanSystem.isPython2():
        return isinstance(someVar, unicode)
    else:
        return isinstance(someVar, str)


def formatString(inputStr, paddingChar="=", totalWidth=80):
    """
    format string, to replace for:
    print '{0:=^80}'.format("xxx");

    auto added space before and after input string
    """
    formatting = "{0:" + paddingChar + "^" + str(totalWidth) + "}"
    return formatting.format(" " + inputStr + " ")


def removeNonWordChar(inputString):
    """
        remove non-word char == only retian alphanumeric character (char+number) and underscore
        eg:
            from againinput4@yeah to againinput4yeah
            from green-waste to greenwaste
    :param inputString:
    :return:
    """
    return re.sub(r"[^\w]", "", inputString)  # non [a-zA-Z0-9_]


def removeInvalidCharInFilename(inputFilename, replacedChar=""):
    """
    Remove invalid char in filename
    eg:
    《神魔手下好当差/穿越之傀儡娃娃》全集
    《神魔手下好当差_穿越之傀儡娃娃》全集
    """
    filteredFilename = inputFilename
    invalidCharList = ['^', '~', '<', '>', '*', '?', '/', '\\', '!']
    for eachInvalidChar in invalidCharList:
        filteredFilename = filteredFilename.replace(eachInvalidChar, replacedChar)
    return filteredFilename


def removeCtlChr(inputString):
    """
        remove control character from input string, otherwise will cause wordpress importer import failed
        for wordpress importer, if contains control char, will fail to import wxr
        eg:
        1. http://againinput4.blog.163.com/blog/static/172799491201110111145259/
        content contains some invalid ascii control chars
        2. http://hi.baidu.com/notebookrelated/blog/item/8bd88e351d449789a71e12c2.html
        165th comment contains invalid control char: ETX
        3. http://green-waste.blog.163.com/blog/static/32677678200879111913911/
        title contains control char:DC1, BS, DLE, DLE, DLE, DC1
    :param inputString:
    :return:
    """
    validContent = ''
    for c in inputString:
        asciiVal = ord(c)
        validChrList = [
            9,  # 9=\t=tab
            10,  # 10=\n=LF=Line Feed=换行
            13,  # 13=\r=CR=回车
        ]
        # filter out others ASCII control character, and DEL=delete
        isValidChr = True
        if (asciiVal == 0x7F):
            isValidChr = False
        elif ((asciiVal < 32) and (asciiVal not in validChrList)):
            isValidChr = False

        if (isValidChr):
            validContent += c

    return validContent


def removeAnsiCtrlChar(inputString):
    """remove ANSI control character: 0x80-0xFF"""
    validContent = ''
    for c in inputString:
        asciiVal = ord(c)
        isValidChr = True
        if ((asciiVal >= 0x80) and (asciiVal <= 0xFF)):
            # if ((asciiVal >= 0xB0) and (asciiVal <= 0xFF)) : # test
            isValidChr = False
            # print "asciiVal=0x%x"%asciiVal

        if (isValidChr):
            validContent += c
    return validContent


def convertToTupleVal(equationStr):
    """
        convert the xxx=yyy into tuple('xxx', yyy), then return the tuple value
        [makesure input string]
        (1) is not include whitespace
        (2) include '='
        (3) last is no ';'
        [possible input string]
        blogUserName="againinput4"
        publisherEmail=""
        synchMiniBlog=false
        publishTime=1322129849397
        publisherName=null
        publisherNickname="\u957F\u5927\u662F\u70E6\u607C"
    :param equationStr:
    :return:
    """
    (key, value) = ('', None)

    try:
        # Note:
        # here should not use split with '=', for maybe input string contains string like this:
        # http://img.bimg.126.net/photo/hmZoNQaqzZALvVp0rE7faA==/0.jpg
        # so use find('=') instead
        firstEqualPos = equationStr.find("=")
        key = equationStr[0:firstEqualPos]
        valuePart = equationStr[(firstEqualPos + 1):]

        # string type
        valLen = len(valuePart)
        if valLen >= 2:
            # maybe string
            if valuePart[0] == '"' and valuePart[-1] == '"':
                # is string type
                value = str(valuePart[1:-1])
            elif (valuePart.lower() == 'null'):
                value = None
            elif (valuePart.lower() == 'false'):
                value = False
            elif (valuePart.lower() == 'true'):
                value = True
            else:
                # must int value
                value = int(valuePart)
        else:
            # len=1 -> must be value
            value = int(valuePart)

        # print "Convert %s to [%s]=%s"%(equationStr, key, value);
    except:
        (key, value) = ('', None)
        print("Fail of convert the equal string %s to value" % (equationStr))

    return key, value


def filterNonAsciiStr(originalUnicodeStr):
    """
        remove (special) non-ascii (special unicode char)
        -> avoid save to ascii occur error:
        UnicodeEncodeError: 'ascii' codec can't encode character u'\u2028' in position 318: ordinal not in range(128)

        eg:
        remove \u2028 from
        Peapack, NJ. \u2028\u2028Mrs. Onassis bought
        in
        http://autoexplosion.com/cars/buy/150631.php

        remove \u201d from
        OC Choppers Super Stretch 124\u201d Softail
        in
        http://autoexplosion.com/bikes/buy/11722.php
    """
    filteredAscii = originalUnicodeStr.encode("ascii", 'ignore')
    filteredUni = filteredAscii.decode("ascii", 'ignore')
    return filteredUni

#----------------------------------------
# JSON
#----------------------------------------


def jsonToStr(jsonDict, indent=2):
    return json.dumps(jsonDict, indent=2, ensure_ascii=False)


def strToJson(jsonStr):
    jsonDict = json.loads(jsonStr, encoding="utf-8")
    return jsonDict


def jsonToPrettyStr(jsonDictOrStr, indent=4, sortKeys=False):
    """
    convert json dictionary un-formatted json string to prettify string

    '{"outputFolder":"output","isResetOutput":true,"waitTimeout":10,"msStore":{"productList":[{"productUrl":"","buyNum":2}]}}'
    ->
    {
        "msStore": {
            "productList": [
                {
                    "productUrl": "",
                    "buyNum": 2
                }
            ]
        },
        "outputFolder": "output",
        "isResetOutput": true,
        "waitTimeout": 10
    }

    :param jsonDictOrStr: json dict or json str
    :param indent: indent space number
    :param sortKeys: output is sort by key or not
    :return: formatted/prettified json string with indent
    """

    prettifiedStr = ""
    jsonDict = jsonDictOrStr
    if type(jsonDictOrStr) is str:
        jsonDict = json.loads(jsonDictOrStr)

    prettifiedStr = json.dumps(jsonDict, indent=indent, sort_keys=sortKeys)
    return prettifiedStr

def saveJsonToFile(jsonDict, fullFilename, indent=2, fileEncoding="utf-8"):
  """
    save dict json into file
    for non-ascii string, output encoded string, without \\u xxxx
  """
  with codecs.open(fullFilename, 'w', encoding="utf-8") as outputFp:
      json.dump(jsonDict, outputFp, indent=indent, ensure_ascii=False)


#----------------------------------------
# String related using chardet
#----------------------------------------


def strIsAscii(strToDect) :
    """
    check whether the strToDect is ASCII string
    Note: should install chardet before use this

    :param strToDect:
    :return:
    """
    isAscii = False
    encInfo = chardet.detect(strToDect)
    if (encInfo['confidence'] > 0.9) and (encInfo['encoding'] == 'ascii'):
        isAscii = True
    return isAscii


def getStrPossibleCharset(inputStr):
    """
    get the possible(possiblility > 0.5) charset of input string

    :param inputStr: input string
    :return: the most possible charset
    """

    possibleCharset = "ascii"
    #possibleCharset = "UTF-8"
    encInfo = chardet.detect(inputStr)
    #print "encInfo=",encInfo
    if (encInfo['confidence'] > 0.5):
        possibleCharset = encInfo['encoding']
    return possibleCharset
    #return encInfo['encoding']


#----------------------------------------
# String related using http
#----------------------------------------

def translateString(strToTranslate, fromLanguage="zh-CHS", toLanguage="EN"):
    """
    translate strToTranslate from fromLanguage to toLanguage

    for supported languages can refer:
        有道智云 -> 帮助与文档 > 产品文档 > 自然语言翻译 > API 文档 > 支持的语言表
        http://ai.youdao.com/docs/doc-trans-api.s#p05

    :param strToTranslate: string to translate
    :param fromLanguage: from language
    :param toLanguage: to language
    :return: translated unicode string
    """

    # logging.debug("translateString: strToTranslate=%s, from=%s, to=%s", strToTranslate, fromLanguage, toLanguage)

    errorCodeDict = {
        101: "缺少必填的参数，出现这个情况还可能是et的值和实际加密方式不对应",
        102: "不支持的语言类型",
        103: "翻译文本过长",
        104: "不支持的API类型",
        105: "不支持的签名类型",
        106: "不支持的响应类型",
        107: "不支持的传输加密类型",
        108: "appKey无效，注册账号， 登录后台创建应用和实例并完成绑定， 可获得应用ID和密钥等信息，其中应用ID就是appKey（ 注意不是应用密钥）",
        109: "batchLog格式不正确",
        110: "无相关服务的有效实例",
        111: "开发者账号无效，可能是账号为欠费状态",
        201: "解密失败，可能为DES,BASE64,URLDecode的错误",
        202: "签名检验失败",
        203: "访问IP地址不在可访问IP列表",
        301: "辞典查询失败",
        302: "翻译查询失败",
        303: "服务端的其它异常",
        401: "账户已经欠费停"
    }

    transOK = False
    translatedStr = strToTranslate
    transErr = ''

    appKey = "152e0e77723a0026"
    saltStr = str(random.randint(1, 65536))
    secretKey = "sYmnnOaisQgZZrlrBFozWAtsaRyyJg4N"
    # logging.debug("appKey=%s,strToTranslate=%s,saltStr=%s,secretKey=%s", appKey, strToTranslate, saltStr, secretKey)
    strToMd5 = appKey + strToTranslate + saltStr + secretKey
    # logging.debug("strToMd5=%s", strToMd5)
    md5Sign = crifanLib.crifanMath.generateMd5(strToMd5)

    try:
        quotedQueryStr = urllib.quote(strToTranslate)
        # transUrl = "http://openapi.youdao.com/api?q=纠删码(EC)的学习&from=zh_CHS&to=EN&appKey=152e0e77723a0026&salt=4&sign=6BE15F1868019AD71C442E6399DB1FE4"
        # transUrl = "http://openapi.youdao.com/api?q=%s&from=zh_CHS&to=EN&appKey=152e0e77723a0026&salt=4&sign=6BE15F1868019AD71C442E6399DB1FE4" % (quotedQueryStr)
        transUrl = "http://openapi.youdao.com/api?q=%s&from=%s&to=%s&appKey=%s&salt=%s&sign=%s" \
                   % (quotedQueryStr, fromLanguage, toLanguage, appKey, saltStr, md5Sign)
        # logging.debug("transUrl=%s", transUrl)
        respJsonStr = crifanLib.crifanHttp.getUrlRespHtml(transUrl)
        # logging.debug("respJsonStr=%s", respJsonStr)
        # respJsonStr={"query":"纠删码(EC)的学习","translation":["The study of correcting code (EC)"],"errorCode":"0","dict":{"url":"yddict://m.youdao.com/dict?le=eng&q=%E7%BA%A0%E5%88%A0%E7%A0%81%28EC%29%E7%9A%84%E5%AD%A6%E4%B9%A0"},"webdict":{"url":"http://m.youdao.com/dict?le=eng&q=%E7%BA%A0%E5%88%A0%E7%A0%81%28EC%29%E7%9A%84%E5%AD%A6%E4%B9%A0"},"l":"zh-CHS2en"}
        translatedDict = json.loads(respJsonStr)
        # logging.debug("translatedDict=%s", translatedDict)
        # translatedDict={u'l': u'zh-CHS2EN', u'errorCode': u'0', u'dict': {u'url': u'yddict://m.youdao.com/dict?le=eng&q=%E9%9B%A2%E5%B3%B6%E9%A2%A8%E5%85%89%E7%9A%84%E6%B5%81%E9%80%A3%E5%BF%98%E8%BF%94'}, u'webdict': {u'url': u'http://m.youdao.com/dict?le=eng&q=%E9%9B%A2%E5%B3%B6%E9%A2%A8%E5%85%89%E7%9A%84%E6%B5%81%E9%80%A3%E5%BF%98%E8%BF%94'}, u'query': u'\u96e2\u5cf6\u98a8\u5149\u7684\u6d41\u9023\u5fd8\u8fd4', u'translation': [u'Away from the island scenery']}

        errorCode = int(translatedDict["errorCode"])
        # logging.debug("errorCode=%s", errorCode)
        errorCodeDictKeys = errorCodeDict.keys()
        # logging.debug("errorCodeDictKeys=%s", errorCodeDictKeys)
        if errorCode != 0:
            if errorCode in errorCodeDictKeys:
                # logging.info("errorCode=%s in errorCodeDictKeys=%s", errorCode, errorCodeDictKeys)
                transOK = False
                transErr = errorCodeDict[errorCode]
                # logging.info("transErr=%s ", transErr)
            else:
                transOK = False
                transErr = "未知错误"
        else:
            queryUnicode = translatedDict["query"]
            translationUnicode = translatedDict["translation"][0]
            # logging.debug(u"queryUnicode=%s, translationUnicode=%s", queryUnicode, translationUnicode)

            transOK = True
            translatedStr = translationUnicode.encode("utf-8")
            # logging.debug("translatedStr=%s ", translatedStr)
    except urllib2.URLError as reason:
        transOK = False
        transErr = reason
    except urllib2.HTTPError as code:
        transOK = False
        transErr = code

    if transOK:
        # logging.info("Translate OK: %s -> %s", strToTranslate, translatedStr)
        return transOK, translatedStr
    else:
        # logging.info("Translate fail for %s", transErr)
        return transOK, transErr


def transZhcnToEn(strToTrans):
    """translate the Chinese(zh-CHS) string to English(EN)"""
    translatedStr = strToTrans
    transOK = False
    transErr = ''

    if strIsAscii(strToTrans):
        transOK = True
        translatedStr = strToTrans
    else:
        # (transOK, translatedStr) = translateString(strToTrans, "zh-CN", "en")
        (transOK, translatedStr) = translateString(strToTrans, "zh-CHS", "EN")

    return transOK, translatedStr



################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))