#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
[Filename]
crifanLib.py

[Function]
crifan's common functions, implemented by Python 2.x.

[Note]
1. online latest version can found at:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib.py

2. detailed explanation about this lib:
crifan的Python库：crifanLib.py
http://www.crifan.com/files/doc/docbook/python_summary/release/html/python_summary.html#crifanlib_py

3. install chardet and BeautifulSoup before use this crifanLib.

[TODO]

[History]
[v5.0, 2017-11-11]
1. add loggingInit
2. updated get current input file name and remove suffix

[v4.9, 2017-10-31]
1.fixbug: update translateString from google translate to youdao translate
1. add generateMd5

[v4.8, 2014-05-23]
1.fixbug-> update translateString to work

[v4.7, 2013-07-02]
1. add initProxy, initProxyAndCookie

[v4.5]
1. add getUrlRespHtml_multiTry
2. updated formatString
3. updated decodeHtmlEntity
4. add filterNonAsciiStr
5. add filterHtmlTag

[v4.0]
1. fixbug of add header in getUrlResponse
2. add getZipcodeFromLocation

[v3.8]
1. add getUrlResponse to support postDataDelimiter.

[v3.7]
1. fixbug -> add user-agent for isFileValid

[v3.6]
1. add formatString

[v3.5]
1.output downloading size support print to same line.
2. add removeInvalidCharInFilename

[v3.4]
1. initAutoHandleCookies support cookie file.

[v3.3]
1.add genListStr

[v3.2]
1. add ConvertELogStrToValue

[v3.1]
1. merge two manuallyDownloadFile int one

[v3.0]
1. add initAutoHandleCookies, getCurrentCookies, printCurrentCookies

[v2.7]
1. add decodeHtmlEntity, htmlEntityCodepointToName, 
2. rename replaceStrEntToNumEnt to htmlEntityNameToCodepoint

[v2.4]
1. add another manuallyDownloadFile with headerDict support

[v2.3]
1. add removeSoupContentsTagAttr, findFirstNavigableString, soupContentsToUnicode

[v2.0]
1. add tupleListToDict

[v1.9]
1.add randDigitsStr

[v1.8]
1.bugfix-> isFileValid support unquoted & lower for compare filename

[v1.7]
1.bugfix-> isFileValid support quoted & lower for compare filename

[v1.6]
1.add getCurTimestamp

[v1.5]
1.add timeout for all urllib2.urlopen to try to avoid dead url link

[v1.4]
1.add support overwrite header for getUrlResponse
2.add gzip support for getUrlResponse and getUrlRespHtml

"""

__author__ = "Crifan Li (admin@crifan.com)"
#__version__ = ""
__copyright__ = "Copyright (c) 2017, Crifan Li"
__license__ = "GPL"

import os
import re
import sys
import time
from datetime import datetime,timedelta

try:
    import chardet
except ImportError:
    print "crifanLib: Can not found lib chardet"

try:
    from BeautifulSoup import BeautifulSoup, Tag, CData
except ImportError:
    print "crifanLib: Can not found lib BeautifulSoup"

import logging
import struct
import zlib
import random
import math
import md5
import json
import urllib
import urllib2
import cookielib

# from PIL import Image;
# from operator import itemgetter;

#Note: The htmlentitydefs module has been renamed to html.entities in Python 3.0.
# so htmlentitydefs is only available between Python 2.3 and Python 2.7
import htmlentitydefs

#--------------------------------const values-----------------------------------
__VERSION__ = "v4.9"

gConst = {
    'UserAgent' : 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)',
    #'UserAgent' : "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
    
    # also belong to ContentTypes, more info can refer: http://kenya.bokee.com/3200033.html
    # here use Tuple to avoid unexpected change
    # note: for tuple, refer item use tuple[i], not tuple(i)
    'picSufList'   : ('bmp', 'gif', 'jpeg', 'jpg', 'jpe', 'png', 'tiff', 'tif'),
    
    'defaultTimeout': 20, # default timeout seconds for urllib2.urlopen
}

#----------------------------------global values--------------------------------
gVal = {
    'calTimeKeyDict'    : {},
    'picSufChars'       : '', # store the pic suffix char list
    
    'currentLevel'      : 0,
    
    'cj'                : None, # used to store current cookiejar, to support auto handle cookies
    'cookieUseFile'     : False,
}


#### some internal functions ###
#------------------------------------------------------------------------------
# generate the suffix char list according to constont picSufList
def genSufList() :
    global gConst;
    
    sufChrList = [];
    for suffix in gConst['picSufList'] :
        for c in suffix :
            sufChrList.append(c);
    sufChrList = uniqueList(sufChrList);
    sufChrList.sort();
    joinedSuf = ''.join(sufChrList);

    swapedSuf = [];
    swapedSuf = joinedSuf.swapcase();

    wholeSuf = joinedSuf + swapedSuf;

    return wholeSuf;

################################################################################
# Math
################################################################################
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
    
    (convertOK, convertedValue) = (False, 0.0);
    foundEPower = re.search("(?P<coefficientPart>-?\d+\.\d+)e(?P<ePowerPart>-\d+)", eLogStr, re.I);
    #print "foundEPower=",foundEPower;
    if(foundEPower):
        coefficientPart = foundEPower.group("coefficientPart");
        ePowerPart = foundEPower.group("ePowerPart");
        #print "coefficientPart=%s,ePower=%s"%(coefficientPart, ePower);
        coefficientValue = float(coefficientPart);
        ePowerValue = float(ePowerPart);
        #print "coefficientValue=%f,ePowerValue=%f"%(coefficientValue, ePowerValue);
        #math.e= 2.71828182846
        wholeOrigValue = coefficientValue * math.pow(math.e, ePowerValue);
        #print "wholeOrigValue=",wholeOrigValue;
        
        (convertOK, convertedValue) = (True, wholeOrigValue);
    else:
        (convertOK, convertedValue) = (False, 0.0);
    
    return (convertOK, convertedValue);

################################################################################
# Time
################################################################################

#------------------------------------------------------------------------------
# get current time's timestamp
# 1351670162
def getCurTimestamp() :
    return datetimeToTimestamp(datetime.now());

#------------------------------------------------------------------------------
# convert datetime value to timestamp
# from "2006-06-01 00:00:00" to 1149091200
def datetimeToTimestamp(datetimeVal) :
    return int(time.mktime(datetimeVal.timetuple()));

#------------------------------------------------------------------------------
# convert timestamp to datetime value
# from 1149091200 to "2006-06-01 00:00:00"
def timestampToDatetime(timestamp) :
    #print "type(timestamp)=",type(timestamp);
    #print "timestamp=",timestamp;
    #timestamp = int(timestamp);
    timestamp = float(timestamp);
    return datetime.fromtimestamp(timestamp);

#------------------------------------------------------------------------------
#init for calculate elapsed time 
def calcTimeStart(uniqueKey) :
    global gVal

    gVal['calTimeKeyDict'][uniqueKey] = time.time();
    return

#------------------------------------------------------------------------------
# to get elapsed time, before call this, should use calcTimeStart to init
def calcTimeEnd(uniqueKey) :
    global gVal

    return time.time() - gVal['calTimeKeyDict'][uniqueKey];
    
################################################################################
# HTML
################################################################################

#------------------------------------------------------------------------------
# convert local GMT8 to GMT time
# note: input should be 'datetime' type, not 'time' type
def convertLocalToGmt(localTime) :
    return localTime - timedelta(hours=8);

def decodeHtmlEntity(origHtml, decodedEncoding=""):
    """Decode html entity (name/decimal code point/hex code point) into unicode char
    eg: from &copy; or &#169; or &#xa9; or &#xA9; to unicode '©'
    
    Note:
    1. Some special char can NOT show in some encoding, such as ©  can NOT show in GBK

    Related knowledge:
    http://www.htmlhelp.com/reference/html40/entities/latin1.html
    http://www.htmlhelp.com/reference/html40/entities/special.html
    
    2.  if processed, then processed string is already is unicode !!!
        if not processed, then still is previous string
    """
    decodedHtml = "";

    #A dictionary mapping XHTML 1.0 entity definitions to their replacement text in ISO Latin-1
    # 'zwnj': '&#8204;',
    # 'aring': '\xe5',
    # 'gt': '>',
    # 'yen': '\xa5',
    #logging.debug("htmlentitydefs.entitydefs=%s", htmlentitydefs.entitydefs);
    
    #A dictionary that maps HTML entity names to the Unicode codepoints
    # 'aring': 229,
    # 'gt': 62,
    # 'sup': 8835,
    # 'Ntilde': 209,
    #logging.debug("htmlentitydefs.name2codepoint=%s", htmlentitydefs.name2codepoint);
    
    #A dictionary that maps Unicode codepoints to HTML entity names
    # 8704: 'forall',
    # 8194: 'ensp',
    # 8195: 'emsp',
    # 8709: 'empty',
    #logging.debug("htmlentitydefs.codepoint2name=%s", htmlentitydefs.codepoint2name);

    #http://fredericiana.com/2010/10/08/decoding-html-entities-to-text-in-python/
    #http://autoexplosion.com/RVs/buy/9882.php
    #will error 
    #not support key : Dryer
    #when use:
    #decodedEntityName = re.sub('&(?P<entityName>[a-zA-Z]{2,10});', lambda matched: unichr(htmlentitydefs.name2codepoint[matched.group("entityName")]), origHtml);

    #logging.debug("origHtml=%s", origHtml);
    def _nameToCodepoint(matched):
        logging.debug("matched=%s", matched);
        wholeStr = matched.group(0);
        logging.debug("wholeStr=%s", wholeStr);
        decodedUnicodeChar = "";
        entityName = matched.group("entityName");
        logging.debug("entityName=%s", entityName);
        if(entityName in htmlentitydefs.name2codepoint):
            decodedCodepoint = htmlentitydefs.name2codepoint[entityName];
            logging.debug("decodedCodepoint=%s", decodedCodepoint);
            decodedUnicodeChar = unichr(decodedCodepoint);
        else:
            #invalid key, just omit it
            
            #http://autoexplosion.com/RVs/buy/9882.php
            #&Dryer;
            #from
            #Washer&Dryer;, Awning,
            decodedUnicodeChar = wholeStr;
        logging.debug("decodedUnicodeChar=%s", decodedUnicodeChar);
        return decodedUnicodeChar;
    decodedEntityName = re.sub('&(?P<entityName>[a-zA-Z]{2,10});', _nameToCodepoint, origHtml);
    #logging.info("decodedEntityName=%s", decodedEntityName);

    #print "type(decodedEntityName)=",type(decodedEntityName); #type(decodedEntityName)= <type 'unicode'>
    decodedCodepointInt = re.sub('&#(?P<codePointInt>\d{2,5});', lambda matched: unichr(int(matched.group("codePointInt"))), decodedEntityName);
    #print "decodedCodepointInt=",decodedCodepointInt;
    decodedCodepointHex = re.sub('&#x(?P<codePointHex>[a-fA-F\d]{2,5});', lambda matched: unichr(int(matched.group("codePointHex"), 16)), decodedCodepointInt);
    #print "decodedCodepointHex=",decodedCodepointHex;

    #logging.info("origHtml=%s", origHtml);
    decodedHtml = decodedCodepointHex;
    #logging.info("decodedHtml=%s", decodedHtml); #type(decodedHtml)= <type 'unicode'>

    #here mabye is unicode string
    if(decodedEncoding):
        # note: here decodedhtml is unicode
        decodedhtml = decodedhtml.encode(decodedEncoding, 'ignore');
        #print "after encode into decodedEncoding=%s, decodedhtml=%s"%(decodedEncoding, decodedhtml);
    
    return decodedHtml;

#------------------------------------------------------------------------------
def htmlEntityNameToCodepoint(htmlWithEntityName):
    """Convert html's entity name into entity code point
    eg: from &nbsp; to &#160; 
    
    related knowledge:
    http://www.htmlhelp.com/reference/html40/entities/latin1.html
    http://www.htmlhelp.com/reference/html40/entities/special.html
    """

    # 'aring':  229,
    # 'gt':     62,
    # 'sup':    8835,
    # 'Ntilde': 209,
    
    # "&aring;":"&#229;",
    # "&gt":    "&#62;",
    # "&sup":   "&#8835;",
    # "&Ntilde":"&#209;",
    nameToCodepointDict = {};
    for eachName in htmlentitydefs.name2codepoint:
        fullName = "&" + eachName + ";";
        fullCodepoint = "&#" + str(htmlentitydefs.name2codepoint[eachName]) + ";";
        nameToCodepointDict[fullName] = fullCodepoint;

    #"&aring;" -> "&#229;"
    htmlWithCodepoint = htmlWithEntityName;
    for key in nameToCodepointDict.keys() :
        htmlWithCodepoint = re.compile(key).sub(nameToCodepointDict[key], htmlWithCodepoint);
    return htmlWithCodepoint;

#------------------------------------------------------------------------------
def htmlEntityCodepointToName(htmlWithCodepoint):
    """Convert html's entity code point into entity name
    eg: from &#160; to &nbsp;
    
    related knowledge:
    http://www.htmlhelp.com/reference/html40/entities/latin1.html
    http://www.htmlhelp.com/reference/html40/entities/special.html
    """
    # 8704: 'forall',
    # 8194: 'ensp',
    # 8195: 'emsp',
    # 8709: 'empty',
    
    # "&#8704;": "&forall;",
    # "&#8194;": "&ensp;",
    # "&#8195;": "&emsp;",
    # "&#8709;": "&empty;",
    codepointToNameDict = {};
    for eachCodepoint in htmlentitydefs.codepoint2name:
        fullCodepoint = "&#" + str(eachCodepoint) + ";";
        fullName = "&" + htmlentitydefs.codepoint2name[eachCodepoint] + ";";
        codepointToNameDict[fullCodepoint] = fullName;

    #"&#160;" -> "&nbsp;"
    htmlWithEntityName = htmlWithCodepoint;
    for key in codepointToNameDict.keys() :
        htmlWithEntityName = re.compile(key).sub(codepointToNameDict[key], htmlWithEntityName);
    return htmlWithEntityName;

def filterHtmlTag(origHtml):
    """
    filter html tag, but retain its contents
    eg:
        Brooklyn, NY 11220<br />
        Brooklyn, NY 11220
        
        <a href="mailto:Bayridgenissan42@yahoo.com">Bayridgenissan42@yahoo.com</a><br />
        Bayridgenissan42@yahoo.com
        
        <a href="javascript:void(0);" onClick="window.open(new Array('http','',':','//','stores.ebay.com','/Bay-Ridge-Nissan-of-New-York?_rdc=1').join(''), '_blank')">stores.ebay.com</a>
        stores.ebay.com
        
        <a href="javascript:void(0);" onClick="window.open(new Array('http','',':','//','www.carfaxonline.com','/cfm/Display_Dealer_Report.cfm?partner=AXX_0&UID=C367031&vin=JH4KB2F61AC001005').join(''), '_blank')">www.carfaxonline.com</a>
        www.carfaxonline.com        
    """
    #logging.info("html tag, origHtml=%s", origHtml);
    filteredHtml = origHtml;

    #Method 1: auto remove tag use re
    #remove br
    filteredHtml = re.sub("<br\s*>", "", filteredHtml, flags=re.I);
    filteredHtml = re.sub("<br\s*/>", "", filteredHtml, flags=re.I);
    #logging.info("remove br, filteredHtml=%s", filteredHtml);
    #remove a
    filteredHtml = re.sub("<a\s+[^<>]+>(?P<aContent>[^<>]+?)</a>", "\g<aContent>", filteredHtml, flags=re.I);
    #logging.info("remove a, filteredHtml=%s", filteredHtml);
    #remove b,strong
    filteredHtml = re.sub("<b>(?P<bContent>[^<>]+?)</b>", "\g<bContent>", filteredHtml, re.I);
    filteredHtml = re.sub("<strong>(?P<strongContent>[^<>]+?)</strong>", "\g<strongContent>", filteredHtml, flags=re.I);
    #logging.info("remove b,strong, filteredHtml=%s", filteredHtml);

    return filteredHtml;

################################################################################
# String
################################################################################

def formatString(inputStr, paddingChar="=", totalWidth=80):
    """
    format string, to replace for:
    print '{0:=^80}'.format("xxx");
    
    auto added space before and after input string
    """
    formatting = "{0:" + paddingChar + "^" + str(totalWidth) + "}";
    return formatting.format(" " + inputStr + " ");
    

def genListStr(listValue, encForUniVal="UTF-8", isRetainLastComma = False, delimiter=","):
    """
    generate string of values in list, separated by delimiter
    eg:
    input: ["20121202", "天平山赏红枫", "动物"]
    output: 20121202,天平山赏红枫,动物
    """
    #print "listValue=",listValue;

    generatedListStr = "";
    for eachValue in listValue:
        if(isinstance(eachValue, unicode)):
            generatedListStr += eachValue.encode(encForUniVal) + delimiter;
        else:
            generatedListStr += str(eachValue) + delimiter;

    if(not isRetainLastComma):
        if(generatedListStr and (generatedListStr[-1] == delimiter)):
            #remove last ,
            generatedListStr = generatedListStr[:-1];
    return generatedListStr;

#------------------------------------------------------------------------------
# generated the random digits number string
# max digit number is 12
def randDigitsStr(digitNum = 12) :
    if(digitNum > 12):
        digitNum = 12;

    randVal = random.random();
    #print "randVal=",randVal; #randVal= 0.134248340235
    randVal = str(randVal);
    #print "randVal=",randVal; #randVal= 0.134248340235
    
    randVal = randVal.replace("0.", "");
    #print "randVal=",randVal; #randVal= 0.134248340235
    
    # if last is 0, append that 0    
    if(len(randVal)==11):
        randVal = randVal + "0";
    #print "randVal=",randVal; #randVal= 0.134248340235
    
    #randVal = randVal.replace("e+11", "");
    #randVal = randVal.replace(".", "");
    #print "randVal=",randVal; #randVal= 0.134248340235
    randVal = randVal[0 : digitNum];
    #print "randVal=",randVal; #randVal= 0.134248340235
    
    return randVal;

#------------------------------------------------------------------------------
# get supported picture suffix list
def getPicSufList():
    return gConst['picSufList'];

#------------------------------------------------------------------------------
# get supported picture suffix chars
def getPicSufChars():
    return gVal['picSufChars'];


def getBasename(fullFilename):
    """
    get base filename

    Examples:
        xxx.exe          -> xxx.exe
        xxx              -> xxx
        Mac/Linux:
           your/path/xxx.py -> xxx.py
        Windows:
           your\path\\xxx.py -> xxx.py
    """

    return os.path.basename(fullFilename)


def removeSuffix(fileBasename):
    """
    remove file suffix

    Examples:
        xxx.exe -> xxx
        xxx -> xxx
    """

    splitedTextArr = os.path.splitext(fileBasename)
    filenameRemovedSuffix = splitedTextArr[0]
    return filenameRemovedSuffix


def getInputFilename():
    """
    get input filename, from argv

    Examples:
        AutoOrder.py -> AutoOrder.py
        python AutoOrder.py -> AutoOrder.py
        python AutoOrder/AutoOrder.py -> AutoOrder/AutoOrder.py
    """

    argvList = sys.argv
    # print "argvList=%s"%(argvList)
    return argvList[0]


def getInputFileBasename(inputFilename = None):
    """
    get input file's base name

    Examples:
        AutoOrder.py -> AutoOrder.py
        AutoOrder/AutoOrder.py -> AutoOrder.py
    """

    curInputFilename = getInputFilename()

    if inputFilename :
        curInputFilename = inputFilename

    # print "curInputFilename=%s"%(curInputFilename)
    inputBasename = getBasename(curInputFilename)
    # print "inputBasename=%s"%(inputBasename)
    return inputBasename

def getInputFileBasenameNoSuffix():
    """
    get input file base name without suffix

    Examples:
        AutoOrder.py -> AutoOrder
        AutoOrder/AutoOrder.py -> AutoOrder
    """

    inputFileBasename = getInputFileBasename()
    basenameRemovedSuffix = removeSuffix(inputFileBasename)
    return basenameRemovedSuffix

#------------------------------------------------------------------------------
# replace the &#N; (N is digit number, N > 1) to unicode char
# eg: replace "&amp;#39;" with "'" in "Creepin&#39; up on you"
def repUniNumEntToChar(text):
    unicodeP = re.compile('&#[0-9]+;');
    def transToUniChr(match): # translate the matched string to unicode char
        numStr = match.group(0)[2:-1]; # remove '&#' and ';'
        num = int(numStr);
        unicodeChar = unichr(num);
        return unicodeChar;
    return unicodeP.sub(transToUniChr, text);

#------------------------------------------------------------------------------
# generate the full url, which include the main url plus the parameter list
# Note: 
# normally just use urllib.urlencode is OK.
# only use this if you do NOT want urllib.urlencode convert some special chars($,:,{,},...) into %XX
def genFullUrl(mainUrl, paraDict) :
    fullUrl = mainUrl;
    fullUrl += '?';
    for i, para in enumerate(paraDict.keys()) :
        if(i == 0):
            # first para no '&'
            fullUrl += str(para) + '=' + str(paraDict[para]);
        else :
            fullUrl += '&' + str(para) + '=' + str(paraDict[para]);
    return fullUrl;

#------------------------------------------------------------------------------
# check whether two url is similar
# note: input two url both should be str type
def urlIsSimilar(url1, url2) :
    isSim = False;

    url1 = str(url1);
    url2 = str(url2);

    slashList1 = url1.split('/');
    slashList2 = url2.split('/');
    lenS1 = len(slashList1);
    lenS2 = len(slashList2);

    # all should have same structure
    if lenS1 != lenS2 :
        # not same sturcture -> must not similar
        isSim = False;
    else :
        sufPos1 = url1.rfind('.');
        sufPos2 = url2.rfind('.');
        suf1 = url1[(sufPos1 + 1) : ];
        suf2 = url2[(sufPos2 + 1) : ];
        # at least, suffix should same
        if (suf1 == suf2) : 
            lastSlashPos1 = url1.rfind('/');
            lastSlashPos2 = url2.rfind('/');
            exceptName1 = url1[:lastSlashPos1];
            exceptName2 = url2[:lastSlashPos2];
            # except name, all other part should same
            if (exceptName1 == exceptName2) :
                isSim = True;
            else :
                # except name, other part is not same -> not similar
                isSim = False;
        else :
            # suffix not same -> must not similar
            isSim = False;

    return isSim;

#------------------------------------------------------------------------------
# found whether the url is similar in urlList
# if found, return True, similarSrcUrl
# if not found, return False, ''
def findSimilarUrl(url, urlList) :
    (isSimilar, similarSrcUrl) = (False, '');
    for srcUrl in urlList :
        if urlIsSimilar(url, srcUrl) :
            isSimilar = True;
            similarSrcUrl = srcUrl;
            break;
    return (isSimilar, similarSrcUrl);

#------------------------------------------------------------------------------
# remove non-word char == only retian alphanumeric character (char+number) and underscore
# eg:
# from againinput4@yeah to againinput4yeah
# from green-waste to greenwaste
def removeNonWordChar(inputString) :
    return re.sub(r"[^\w]", "", inputString); # non [a-zA-Z0-9_]

def removeInvalidCharInFilename(inputFilename, replacedChar=""):
	"""
	Remove invalid char in filename
	eg: 
	《神魔手下好当差/穿越之傀儡娃娃》全集
	《神魔手下好当差_穿越之傀儡娃娃》全集
	"""
	filteredFilename = inputFilename;
	invalidCharList = ['^', '~', '<', '>', '*', '?', '/', '\\', '!'];
	for eachInvalidChar in invalidCharList:
		filteredFilename = filteredFilename.replace(eachInvalidChar, replacedChar);
	return filteredFilename;

#------------------------------------------------------------------------------
# remove control character from input string
# otherwise will cause wordpress importer import failed
# for wordpress importer, if contains contrl char, will fail to import wxr
# eg:
# 1. http://againinput4.blog.163.com/blog/static/172799491201110111145259/
# content contains some invalid ascii control chars
# 2. http://hi.baidu.com/notebookrelated/blog/item/8bd88e351d449789a71e12c2.html
# 165th comment contains invalid control char: ETX
# 3. http://green-waste.blog.163.com/blog/static/32677678200879111913911/
# title contains control char:DC1, BS, DLE, DLE, DLE, DC1
def removeCtlChr(inputString) :
    validContent = '';
    for c in inputString :
        asciiVal = ord(c);
        validChrList = [
            9, # 9=\t=tab
            10, # 10=\n=LF=Line Feed=换行
            13, # 13=\r=CR=回车
        ];
        # filter out others ASCII control character, and DEL=delete
        isValidChr = True;
        if (asciiVal == 0x7F) :
            isValidChr = False;
        elif ((asciiVal < 32) and (asciiVal not in validChrList)) :
            isValidChr = False;
        
        if(isValidChr) :
            validContent += c;

    return validContent;

#------------------------------------------------------------------------------
# remove ANSI control character: 0x80-0xFF
def removeAnsiCtrlChar(inputString):
    validContent = '';
    for c in inputString :
        asciiVal = ord(c);
        isValidChr = True;
        if ((asciiVal >= 0x80) and (asciiVal <= 0xFF)) :
        #if ((asciiVal >= 0xB0) and (asciiVal <= 0xFF)) : # test
            isValidChr = False;
            #print "asciiVal=0x%x"%asciiVal;

        if(isValidChr) :
            validContent += c;
    return validContent;

#------------------------------------------------------------------------------
# convert the xxx=yyy into tuple('xxx', yyy), then return the tuple value
# [makesure input string]
# (1) is not include whitespace
# (2) include '='
# (3) last is no ';'
# [possible input string]
# blogUserName="againinput4"
# publisherEmail=""
# synchMiniBlog=false
# publishTime=1322129849397
# publisherName=null
# publisherNickname="\u957F\u5927\u662F\u70E6\u607C"
def convertToTupleVal(equationStr) :
    (key, value) = ('', None);

    try :
        # Note:
        # here should not use split with '=', for maybe input string contains string like this:
        # http://img.bimg.126.net/photo/hmZoNQaqzZALvVp0rE7faA==/0.jpg
        # so use find('=') instead
        firstEqualPos = equationStr.find("=");
        key = equationStr[0:firstEqualPos];
        valuePart = equationStr[(firstEqualPos + 1):];

        # string type
        valLen = len(valuePart);
        if valLen >= 2 :
            # maybe string
            if valuePart[0] == '"' and valuePart[-1] == '"' :
                # is string type
                value = str(valuePart[1:-1]);
            elif (valuePart.lower() == 'null'):
                value = None;
            elif (valuePart.lower() == 'false'):
                value = False;
            elif (valuePart.lower() == 'true') :
                value = True;
            else :
                # must int value
                value = int(valuePart);
        else :
            # len=1 -> must be value
            value = int(valuePart);

        #print "Convert %s to [%s]=%s"%(equationStr, key, value);
    except :
        (key, value) = ('', None);
        print "Fail of convert the equal string %s to value"%(equationStr);

    return (key, value);

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
    
    filteredAscii = originalUnicodeStr.encode("ascii", 'ignore');
    filteredUni = filteredAscii.decode("ascii", 'ignore');
    
    return filteredUni;

################################################################################
# List
################################################################################

#------------------------------------------------------------------------------
# remove the empty ones in list
def removeEmptyInList(list) :
    newList = [];
    for val in list :
        if val :
            newList.append(val);
    return newList;

#------------------------------------------------------------------------------
# remove overlapped item in the list
def uniqueList(old_list):
    newList = []
    for x in old_list:
        if x not in newList :
            newList.append(x)
    return newList

#------------------------------------------------------------------------------
# for listToFilter, remove the ones which is in listToCompare
# also return the ones which is already exist in listToCompare
def filterList(listToFilter, listToCompare) :
    filteredList = [];
    existedList = [];
    for singleOne in listToFilter : # remove processed
        if (not(singleOne in listToCompare)) :
            # omit the ones in listToCompare
            filteredList.append(singleOne);
        else :
            # record the already exist ones
            existedList.append(singleOne);
    return (filteredList, existedList);
    
#------------------------------------------------------------------------------
# convert tuple list to dict value
# [(u'type', u'text/javascript'), (u'src', u'http://partner.googleadservices.com/gampad/google_service.js')]
# { u'type':u'text/javascript', u'src':u'http://partner.googleadservices.com/gampad/google_service.js' }
def tupleListToDict(tupleList):
    convertedDict = {};
    
    for eachTuple in tupleList:
        (key, value) = eachTuple;
        convertedDict[key] = value;
    
    return convertedDict;

################################################################################
# File
################################################################################

#------------------------------------------------------------------------------
# save binary data into file
def saveBinDataToFile(binaryData, fileToSave):
    saveOK = False;
    try:
        savedBinFile = open(fileToSave, "wb"); # open a file, if not exist, create it
        #print "savedBinFile=",savedBinFile;
        savedBinFile.write(binaryData);
        savedBinFile.close();
        saveOK = True;
    except :
        saveOK = False;
    return saveOK;


################################################################################
# Cookies
################################################################################

def initAutoHandleCookies(localCookieFileName=None):
    """Add cookiejar to support auto handle cookies.
    support designate cookie file
    
    Note:
    after this init, later urllib2.urlopen will automatically handle cookies
    """

    if(localCookieFileName):
        gVal['cookieUseFile'] = True;
        #print "use cookie file";
        
        #gVal['cj'] = cookielib.FileCookieJar(localCookieFileName); #NotImplementedError
        gVal['cj'] = cookielib.LWPCookieJar(localCookieFileName); # prefer use this
        #gVal['cj'] = cookielib.MozillaCookieJar(localCookieFileName); # second consideration
        #create cookie file
        gVal['cj'].save();
    else:
        #print "not use cookie file";
        gVal['cookieUseFile'] = False;
        
        gVal['cj'] = cookielib.CookieJar();

    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(gVal['cj']));
    urllib2.install_opener(opener);

    #print "Auto handle cookies inited OK";
    return;

def initProxy(singleProxyDict = {}):
    """Add proxy support for later urllib2 auto use this proxy
    
    Note:
    1. tmp not support username and password
    2. after this init, later urllib2.urlopen will automatically use this proxy
    """

    proxyHandler = urllib2.ProxyHandler(singleProxyDict);
    #print "proxyHandler=",proxyHandler;
    proxyOpener = urllib2.build_opener(proxyHandler);
    #print "proxyOpener=",proxyOpener;
    urllib2.install_opener(proxyOpener);
    
    return;
    
def initProxyAndCookie(singleProxyDict = {}, localCookieFileName=None):
    """Init proxy and cookie
    
    Note:
    1. after this init, later urllib2.urlopen will auto, use proxy, auto handle cookies
    2. for proxy, tmp not support username and password
    """

    proxyHandler = urllib2.ProxyHandler(singleProxyDict);
    #print "proxyHandler=",proxyHandler;
    
    if(localCookieFileName):
        gVal['cookieUseFile'] = True;
        #print "use cookie file";
        
        #gVal['cj'] = cookielib.FileCookieJar(localCookieFileName); #NotImplementedError
        gVal['cj'] = cookielib.LWPCookieJar(localCookieFileName); # prefer use this
        #gVal['cj'] = cookielib.MozillaCookieJar(localCookieFileName); # second consideration
        #create cookie file
        gVal['cj'].save();
    else:
        #print "not use cookie file";
        gVal['cookieUseFile'] = False;
        
        gVal['cj'] = cookielib.CookieJar();

    proxyAndCookieOpener = urllib2.build_opener(urllib2.HTTPCookieProcessor(gVal['cj']), proxyHandler);
    #print "proxyAndCookieOpener=",proxyAndCookieOpener;
    urllib2.install_opener(proxyAndCookieOpener);
    
    return;
    
#------------------------------------------------------------------------------
def getCurrentCookies():
    """Return current cookies.
    
    Note:
    only call this this function, if you previously called initAutoHandleCookies
    """
    return gVal['cj'];

#------------------------------------------------------------------------------
def printCurrentCookies():
    """Just print current cookies for debug simplicity.
    """
    if(gVal['cj']):
        for index, cookie in enumerate(gVal['cj']):
            print "[%d] name=%s,value=%s,domain=%s,path=%s,secure=%s,expires=%s,version=%d"% \
                (index, cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure, cookie.expires, cookie.version);

#------------------------------------------------------------------------------
def checkAllCookiesExist(cookieNameList, cookieJar) :
    """Check all cookies('s name) in cookiesDict is exist in cookieJar or not"""
    cookiesDict = {};
    for eachCookieName in cookieNameList :
        cookiesDict[eachCookieName] = False;
    
    allCookieFound = True;
    for cookie in cookieJar :
        if(cookie.name in cookiesDict) :
            cookiesDict[cookie.name] = True;
    
    for eachCookie in cookiesDict.keys() :
        if(not cookiesDict[eachCookie]) :
            allCookieFound = False;
            break;

    return allCookieFound;

################################################################################
# Network: urllib/urllib2/http
################################################################################

#------------------------------------------------------------------------------
# check file validation:
# open file url to check return info is match or not
# with exception support
# note: should handle while the file url is redirect
# eg :
# http://publish.it168.com/2007/0627/images/500754.jpg ->
# http://img.publish.it168.com/2007/0627/images/500754.jpg
# other special one:
# sina pic url: 
# http://s14.sinaimg.cn/middle/3d55a9b7g9522d474a84d&690
# http://s14.sinaimg.cn/orignal/3d55a9b7g9522d474a84d
# the real url is same with above url
def isFileValid(fileUrl) :
    fileIsValid = False;
    errReason = "Unknown error";

    try :
        #print "original fileUrl=",fileUrl;
        origFileName = fileUrl.split('/')[-1];
        #print "origFileName=",origFileName;
        
        #old: https://ie2zeq.bay.livefilestore.com/y1mo7UWr-TrmqbBhkw52I0ii__WE6l2UtMRSTZHSky66-uDxnCdKPr3bdqVrpUcQHcoJLedlFXa43bvCp_O0zEGF3JdG_yZ4wRT-c2AQmJ_TNcWvVZIXfBDgGerouWyx19WpA4I0XQR1syRJXjDNpwAbQ/IMG_5214_thumb[1].jpg
        #new: https://kxoqva.bay.livefilestore.com/y1mQlGjwNAYiHKoH5Aw6TMNhsCmX2YDR3vPKnP86snuqQEtnZgy3dHkwUvZ61Ah8zU3AGiS4whmm_ADrvxdufEAfMGo56KjLdhIbosn9F34olQ/IMG_5214_thumb%5b1%5d.jpg
        unquotedOrigFilenname = urllib.unquote(origFileName);
        #print "unquotedOrigFilenname=",unquotedOrigFilenname
        lowUnquotedOrigFilename = unquotedOrigFilenname.lower();
        #print "lowUnquotedOrigFilename=",lowUnquotedOrigFilename;
        
        #resp = urllib2.urlopen(fileUrl, timeout=gConst['defaultTimeout']); # note: Python 2.6 has added timeout support.
        #some url, such as
        #http://my.csdn.net/uploads/201205/03/1336006009_2164.jpg
        #if not give user-agent, then will error: HTTP Error 403: Forbidden
        request = urllib2.Request(fileUrl, headers={'User-Agent' : gConst['UserAgent']});
        #print "request=",request;
        resp = urllib2.urlopen(request, timeout=gConst['defaultTimeout']);
        
        #print "resp=",resp;
        realUrl = resp.geturl();
        #print "realUrl=",realUrl;
        newFilename = realUrl.split('/')[-1];
        #print "newFilename=",newFilename;
        
        #http://blog.sina.com.cn/s/blog_696e50390100ntxs.html
        unquotedNewFilename = urllib.unquote(newFilename);
        #print "unquotedNewFilename=",unquotedNewFilename;
        unquotedLowNewFilename = unquotedNewFilename.lower();
        #print "unquotedLowNewFilename=",unquotedLowNewFilename;
        
        respInfo = resp.info();
        #print "respInfo=",respInfo;
        respCode = resp.getcode();
        #print "respCode=",respCode;

        # special:
        # http://116.img.pp.sohu.com/images/blog/2007/5/24/17/24/11355bf42a9.jpg
        # return no content-length
        #contentLen = respInfo['Content-Length'];
        
        # for redirect, if returned size>0 and filename is same, also should be considered valid
        #if (origFileName == newFilename) and (contentLen > 0):
        # for redirect, if returned response code is 200(OK) and filename is same, also should be considered valid
        #if (origFileName == newFilename) and (respCode == 200):
        if (lowUnquotedOrigFilename == unquotedLowNewFilename) and (respCode == 200):
            fileIsValid = True;
        else :
            fileIsValid = False;
            
            # eg: Content-Type= image/gif, ContentTypes : audio/mpeg
            # more ContentTypes can refer: http://kenya.bokee.com/3200033.html
            contentType = respInfo['Content-Type'];
        
            errReason = "file url returned info: type=%s, len=%d, realUrl=%s"%(contentType, contentLen, realUrl);
    except urllib2.URLError,reason :
        fileIsValid = False;
        errReason = reason;
    except urllib2.HTTPError,code :
        fileIsValid = False;
        errReason = code;
    except :
        fileIsValid = False;
        errReason = "Unknown error";

    # here type(errReason)= <class 'urllib2.HTTPError'>, so just convert it to str
    errReason = str(errReason);
    return (fileIsValid, errReason);

#------------------------------------------------------------------------------
# download from fileUrl then save to fileToSave
# with exception support
# note: the caller should make sure the fileUrl is a valid internet resource/file
def downloadFile(fileUrl, fileToSave, needReport = False) :
    isDownOK = False;
    downloadingFile = '';

    #---------------------------------------------------------------------------
    # note: totalFileSize -> may be -1 on older FTP servers which do not return a file size in response to a retrieval request
    def reportHook(copiedBlocks, blockSize, totalFileSize) :
        #global downloadingFile
        if copiedBlocks == 0 : # 1st call : once on establishment of the network connection
            print 'Begin to download %s, total size=%d'%(downloadingFile, totalFileSize);
        else : # rest call : once after each block read thereafter
            print 'Downloaded bytes: %d\r' % ( blockSize * copiedBlocks),;
        return;
    #---------------------------------------------------------------------------

    try :
        if fileUrl :
            downloadingFile = fileUrl;
            if needReport :
                urllib.urlretrieve(fileUrl, fileToSave, reportHook);
            else :
                urllib.urlretrieve(fileUrl, fileToSave);
            isDownOK = True;
        else :
            print "Input download file url is NULL";
    except urllib.ContentTooShortError(msg) :
        isDownOK = False;
    except :
        isDownOK = False;

    return isDownOK;

#------------------------------------------------------------------------------
def manuallyDownloadFile(fileUrl, fileToSave, headerDict=""):
    """manually download fileUrl then save to fileToSave, with header support"""
    
    isDownOK = False;
    errReason = "No error";
    
    try :
        if fileUrl :
            respHtml = "";
            if(headerDict):
                respHtml = getUrlRespHtml(fileUrl, headerDict=headerDict,useGzip=False, timeout=gConst['defaultTimeout']);
            else:
                # 1. find real address
                #print "fileUrl=",fileUrl;
                resp = urllib2.urlopen(fileUrl, timeout=gConst['defaultTimeout']);
                #print "resp=",resp;
                realUrl = resp.geturl(); # not same with original file url if redirect
                # if url is invalid, then add timeout can avoid dead
                respHtml = getUrlRespHtml(realUrl, useGzip=False, timeout=gConst['defaultTimeout']);
            
            if(respHtml):
                isDownOK = saveBinDataToFile(respHtml, fileToSave);
        else :
            print "Input download file url is NULL";
    except urllib2.URLError,reason:
        isDownOK = False;
        errReason = reason;
    except urllib2.HTTPError,code :
        isDownOK = False;
        errReason = code;
    except :
        isDownOK = False;
        errReason = "Unknown error";

    #print "isDownOK=%s, errReason=%s"%(isDownOK, errReason);
    return isDownOK;

#------------------------------------------------------------------------------
def getUrlResponse(url, postDict={}, headerDict={}, timeout=0, useGzip=False, postDataDelimiter="&") :
    """Get response from url, support optional postDict,headerDict,timeout,useGzip

    Note:
    1. if postDict not null, url request auto become to POST instead of default GET
    2  if you want to auto handle cookies, should call initAutoHandleCookies() before use this function.
       then following urllib2.Request will auto handle cookies
    """

    # makesure url is string, not unicode, otherwise urllib2.urlopen will error
    url = str(url);

    if (postDict) :
        if(postDataDelimiter=="&"):
            postData = urllib.urlencode(postDict);
        else:
            postData = "";
            for eachKey in postDict.keys() :
                postData += str(eachKey) + "="  + str(postDict[eachKey]) + postDataDelimiter;
        postData = postData.strip();
        #logging.info("postData=%s", postData);
        req = urllib2.Request(url, postData);
        #logging.info("req=%s", req);
        req.add_header('Content-Type', "application/x-www-form-urlencoded");
    else :
        req = urllib2.Request(url);

    defHeaderDict = {
        'User-Agent'    : gConst['UserAgent'],
        'Cache-Control' : 'no-cache',
        'Accept'        : '*/*',
        'Connection'    : 'Keep-Alive',
    };

    # add default headers firstly
    for eachDefHd in defHeaderDict.keys() :
        #print "add default header: %s=%s"%(eachDefHd,defHeaderDict[eachDefHd]);
        req.add_header(eachDefHd, defHeaderDict[eachDefHd]);

    if(useGzip) :
        #print "use gzip for",url;
        req.add_header('Accept-Encoding', 'gzip, deflate');

    # add customized header later -> allow overwrite default header 
    if(headerDict) :
        #print "added header:",headerDict;
        for key in headerDict.keys() :
            req.add_header(key, headerDict[key]);

    if(timeout > 0) :
        # set timeout value if necessary
        resp = urllib2.urlopen(req, timeout=timeout);
    else :
        resp = urllib2.urlopen(req);
        
    #update cookies into local file
    if(gVal['cookieUseFile']):
        gVal['cj'].save();
        # logging.info("gVal['cj']=%s", gVal['cj']);
    
    return resp;

#------------------------------------------------------------------------------
# get response html==body from url
#def getUrlRespHtml(url, postDict={}, headerDict={}, timeout=0, useGzip=False) :
def getUrlRespHtml(url, postDict={}, headerDict={}, timeout=0, useGzip=True, postDataDelimiter="&") :
    resp = getUrlResponse(url, postDict, headerDict, timeout, useGzip, postDataDelimiter);
    respHtml = resp.read();
    
    #here, maybe, even if not send Accept-Encoding: gzip, deflate
    #but still response gzip or deflate, so directly do undecompress
    #if(useGzip) :
    
    #print "---before unzip, len(respHtml)=",len(respHtml);
    respInfo = resp.info();
    
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
    
    #Content-Encoding: deflate
    if("Content-Encoding" in respInfo):
        if("gzip" == respInfo['Content-Encoding']):
            respHtml = zlib.decompress(respHtml, 16+zlib.MAX_WBITS);
        elif("deflate" == respInfo['Content-Encoding']):
            respHtml = zlib.decompress(respHtml, -zlib.MAX_WBITS);

    return respHtml;

def getUrlRespHtml_multiTry(url, postDict={}, headerDict={}, timeout=0, useGzip=True, postDataDelimiter="&", maxTryNum=5):
    """
        get url response html, multiple try version:
            if fail, then retry
    """
    respHtml = "";
    
    # access url
    # mutile retry, if some (mostly is network) error
    for tries in range(maxTryNum) :
        try :
            respHtml = getUrlRespHtml(url, postDict, headerDict, timeout, useGzip, postDataDelimiter);
            #logging.debug("Successfully access url %s", url);
            break # successfully, so break now
        except :
            if tries < (maxTryNum - 1) :
                #logging.warning("Access url %s fail, do %d retry", url, (tries + 1));
                continue;
            else : # last try also failed, so exit
                logging.error("Has tried %d times to access url %s, all failed!", maxTryNum, url);
                break;

    return respHtml;
    

################################################################################
# Image
################################################################################

# import Image,ImageEnhance,ImageFilter;


# def testCaptcha():
    # #http://www.pythonclub.org/project/captcha/python-pil
    
    # #image_name = "20120409_134346_captcha.jpg";
    # #image_name = "20120409_134531_captcha.jpg";
    # #image_name = "20120409_134625_captcha.jpg";
    # #image_name = "20120409_134928_captcha.jpg";
    # image_name = "20120409_135233_captcha.jpg";
    
    # im = Image.open(image_name);
    # print "open OK for=",image_name;
    # filter = ImageFilter.MedianFilter();
    # print "MedianFilter OK";
    # im = im.filter(filter);
    # print "filter OK";
    # enhancer = ImageEnhance.Contrast(im);
    # print "Contrast OK";
    # im = enhancer.enhance(2);
    # print "enhance OK"; 
    # im = im.convert('1');
    # print "convert OK"; 
    # #im.show()
    # #print "show OK"; 
    
    # im.save(image_name + "_new.gif"); 
    # print "save OK"; 
    
    # ooooooooooooooooo

# #------------------------------------------------------------------------------
# # [uncompleted]
# # parse input picture file to captcha(verify code)
# def parseCaptchaFromPicFile(inputCaptFilename):
    # #http://www.wausita.com/captcha/
    
    # parsedCaptchaStr = "";
    
    
    # # picFp = open(inputCaptFilename, "rb");
    # # print "open pic file OK,picFp=",picFp;
    # # picData = picFp.read();
    # # print "read pic file OK";
    # # picFp.close();
    # # print "len(picData)=",len(picData);


    # print "------------------capta test begin -----------------";
    # captchaDir = "captcha";
    # #inputCaptFilename = "returned_captcha.jpg";
    # #inputCaptFilename = "captcha.gif";
    # print "inputCaptFilename=",inputCaptFilename;
    # inputCaptFilename = inputCaptFilename.split("/")[-1];
    # captchaPicFile = captchaDir + "/" + inputCaptFilename;
    # print "captchaPicFile=",captchaPicFile;
    
    # im = Image.open(captchaPicFile);
    # im = im.convert("P");
    # im2 = Image.new("P", im.size, 255);

    # temp = {};

    # # 225 571
    # # 219 253
    # # 189 82
    # # 132 64
    # # 90 63
    # # 224 63
    # # 139 48
    # # 182 47
    # # 133 43
    # # 96 39



    # his = im.histogram();

    # print im.histogram();

    # values = {};

    # for i in range(256):
      # values[i] = his[i];

    # mostCommonColor = sorted(values.items(), key=itemgetter(1), reverse=True)[:10];
    # print type(mostCommonColor);
    
    # print "-----most 0-9:-----";
    # for key in mostCommonColor:
        # #print type(key);
        # print key;

    # startIdx = 0;
    # endIdx = 3;
    # outputGifName = captchaPicFile + "_from-%d_to-%d.gif"%(startIdx, endIdx);

    # #mostCommonColor = mostCommonColor[0:3]; # good result -> 0.8 similar
    # #mostCommonColor = mostCommonColor[0:2]; # not bad result -> 0.7 similar
    # mostCommonColor = mostCommonColor[startIdx:endIdx];
    
    # print "-----most %d-%d:-----"%(startIdx, endIdx);
    # for j,k in mostCommonColor:
      # print j,k;
    

    # mostCommonColorDict = dict(mostCommonColor);
    # print mostCommonColorDict;
    
    # for x in range(im.size[1]):
        # for y in range(im.size[0]):
            # pix = im.getpixel((y,x));
            # temp[pix] = pix;
            # #if pix == 220 or pix == 227: # these are the numbers to get
            # if pix in mostCommonColorDict:
                # #print pix;
                # im2.putpixel((y,x),0);

    # im2.save(outputGifName);    
   
    # print "------------------capta test done -----------------";

    # return parsedCaptchaStr;
    
    
################################################################################
# Functions that depend on third party lib
################################################################################

#------------------------------------------------------------------------------
# depend on chardet
# check whether the strToDect is ASCII string
def strIsAscii(strToDect) :
    isAscii = False;
    encInfo = chardet.detect(strToDect);
    if (encInfo['confidence'] > 0.9) and (encInfo['encoding'] == 'ascii') :
        isAscii = True;
    return isAscii;


def getStrPossibleCharset(inputStr) :
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
    logging.debug("encrptedMd5=%s", encrptedMd5)
    #encrptedMd5=af0230c7fcc75b34cbb268b9bf64da79

    return encrptedMd5


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

    logging.debug("translateString: strToTranslate=%s, from=%s, to=%s", strToTranslate, fromLanguage, toLanguage)

    errorCodeDict = {
        101	: "缺少必填的参数，出现这个情况还可能是et的值和实际加密方式不对应",
        102	: "不支持的语言类型",
        103	: "翻译文本过长",
        104	: "不支持的API类型",
        105	: "不支持的签名类型",
        106	: "不支持的响应类型",
        107	: "不支持的传输加密类型",
        108	: "appKey无效，注册账号， 登录后台创建应用和实例并完成绑定， 可获得应用ID和密钥等信息，其中应用ID就是appKey（ 注意不是应用密钥）",
        109	: "batchLog格式不正确",
        110	: "无相关服务的有效实例",
        111	: "开发者账号无效，可能是账号为欠费状态",
        201	: "解密失败，可能为DES,BASE64,URLDecode的错误",
        202	: "签名检验失败",
        203	: "访问IP地址不在可访问IP列表",
        301	: "辞典查询失败",
        302	: "翻译查询失败",
        303	: "服务端的其它异常",
        401	: "账户已经欠费停"        
    }

    transOK = False
    translatedStr = strToTranslate
    transErr = ''

    appKey = "152e0e77723a0026"
    saltStr = str(random.randint(1, 65536))
    secretKey = "sYmnnOaisQgZZrlrBFozWAtsaRyyJg4N"
    logging.debug("appKey=%s,strToTranslate=%s,saltStr=%s,secretKey=%s", appKey, strToTranslate, saltStr, secretKey)
    strToMd5 = appKey + strToTranslate + saltStr + secretKey
    logging.debug("strToMd5=%s", strToMd5)
    md5Sign = generateMd5(strToMd5)

    try :
        quotedQueryStr = urllib.quote(strToTranslate)
        #transUrl = "http://openapi.youdao.com/api?q=纠删码(EC)的学习&from=zh_CHS&to=EN&appKey=152e0e77723a0026&salt=4&sign=6BE15F1868019AD71C442E6399DB1FE4"
        # transUrl = "http://openapi.youdao.com/api?q=%s&from=zh_CHS&to=EN&appKey=152e0e77723a0026&salt=4&sign=6BE15F1868019AD71C442E6399DB1FE4" % (quotedQueryStr)
        transUrl = "http://openapi.youdao.com/api?q=%s&from=%s&to=%s&appKey=%s&salt=%s&sign=%s" \
            % (quotedQueryStr, fromLanguage, toLanguage, appKey, saltStr, md5Sign)
        logging.debug("transUrl=%s", transUrl)
        respJsonStr = getUrlRespHtml(transUrl)
        logging.debug("respJsonStr=%s", respJsonStr)
        # respJsonStr={"query":"纠删码(EC)的学习","translation":["The study of correcting code (EC)"],"errorCode":"0","dict":{"url":"yddict://m.youdao.com/dict?le=eng&q=%E7%BA%A0%E5%88%A0%E7%A0%81%28EC%29%E7%9A%84%E5%AD%A6%E4%B9%A0"},"webdict":{"url":"http://m.youdao.com/dict?le=eng&q=%E7%BA%A0%E5%88%A0%E7%A0%81%28EC%29%E7%9A%84%E5%AD%A6%E4%B9%A0"},"l":"zh-CHS2en"}
        translatedDict = json.loads(respJsonStr)
        logging.debug("translatedDict=%s", translatedDict)
        # translatedDict={u'l': u'zh-CHS2EN', u'errorCode': u'0', u'dict': {u'url': u'yddict://m.youdao.com/dict?le=eng&q=%E9%9B%A2%E5%B3%B6%E9%A2%A8%E5%85%89%E7%9A%84%E6%B5%81%E9%80%A3%E5%BF%98%E8%BF%94'}, u'webdict': {u'url': u'http://m.youdao.com/dict?le=eng&q=%E9%9B%A2%E5%B3%B6%E9%A2%A8%E5%85%89%E7%9A%84%E6%B5%81%E9%80%A3%E5%BF%98%E8%BF%94'}, u'query': u'\u96e2\u5cf6\u98a8\u5149\u7684\u6d41\u9023\u5fd8\u8fd4', u'translation': [u'Away from the island scenery']}

        errorCode = int(translatedDict["errorCode"])
        # logging.debug("errorCode=%s", errorCode)
        errorCodeDictKeys = errorCodeDict.keys()
        # logging.debug("errorCodeDictKeys=%s", errorCodeDictKeys)
        if errorCode != 0 :
            if errorCode in errorCodeDictKeys :
                # logging.info("errorCode=%s in errorCodeDictKeys=%s", errorCode, errorCodeDictKeys)
                transOK = False
                transErr = errorCodeDict[errorCode]
                # logging.info("transErr=%s ", transErr)
            else :
                transOK = False
                transErr = "未知错误"
        else :
            queryUnicode = translatedDict["query"]
            translationUnicode = translatedDict["translation"][0]
            logging.debug(u"queryUnicode=%s, translationUnicode=%s", queryUnicode, translationUnicode)

            transOK = True
            translatedStr = translationUnicode.encode("utf-8")
            logging.debug("translatedStr=%s ", translatedStr)
    except urllib2.URLError,reason :
        transOK = False
        transErr = reason
    except urllib2.HTTPError,code :
        transOK = False
        transErr = code

    if transOK :
        logging.info("Translate OK: %s -> %s", strToTranslate, translatedStr)
        return (transOK, translatedStr)
    else :
        logging.info("Translate fail for %s", transErr)
        return (transOK, transErr)

#------------------------------------------------------------------------------
# translate the Chinese(zh-CHS) string to English(EN)
def transZhcnToEn(strToTrans) :
    translatedStr = strToTrans
    transOK = False
    transErr = ''

    if strIsAscii(strToTrans) :
        transOK = True
        translatedStr = strToTrans
    else :
        # (transOK, translatedStr) = translateString(strToTrans, "zh-CN", "en")
        (transOK, translatedStr) = translateString(strToTrans, "zh-CHS", "EN")

    return (transOK, translatedStr)

def getZipcodeFromLocation(locationStr):
    """
        get zip code from location string, especially for USA
        eg: 
        intput: Tampa, FL
        output: 33601
        
        input: West Palm Beach, FL
        output: 33401
    """
    zipCode = "";
    gotZipCode = False;
    
    if(not gotZipCode):
        #Method 1: 
        #http://autoexplosion.com/templates/zip_search.php
        cityStateList = locationStr.split(",");
        logging.debug("cityStateList=%s", cityStateList);
        city = cityStateList[0].strip();
        state = cityStateList[1].strip();
        logging.debug("city=%s, state=%s", city, state);
        #http://autoexplosion.com/templates/zip_search.php?formname=search&city=Tampa&state=FL
        zipBaseSearchUrl = "http://autoexplosion.com/templates/zip_search.php";
        paraDict = {
            'formname'  : "search",
            'city'      : city,
            'state'     : state,
        };
        #http://autoexplosion.com/templates/zip_search.php?city=San Antonio&state=TX&formname=search
        encodedPara = urllib.urlencode(paraDict);
        logging.debug("encodedPara=%s", encodedPara);
            
        #zipSearchUrl = genFullUrl(zipBaseSearchUrl, paraDict);
        zipSearchUrl = zipBaseSearchUrl + "?" + encodedPara;
        logging.debug("zipSearchUrl=%s", zipSearchUrl);
        
        headerDict = {
            'Referer'   : "http://autoexplosion.com/templates/zip_search.php?formname=search",
        };
        zipSearchRespHtml = getUrlRespHtml(zipSearchUrl, headerDict=headerDict);
        logging.debug("zipSearchRespHtml=%s", zipSearchRespHtml);

        #found the first zip search result
        # <tr>				<td colspan="2" class="cssTableCellLeft">&nbsp;San Antonio</td>
                        # <td align="center">TX</td>
                        # <td colspan="2" align="center" class="cssTableCellRight"><a href="javascript:paste_zip('78201');">78201</a></td>
                    # </tr>
        soup = BeautifulSoup(zipSearchRespHtml);
        foundZipcode = soup.find(name="td", attrs={"class":"cssTableCellRight"});
        logging.debug("foundZipcode=%s", foundZipcode);
        if(foundZipcode):
            zipCode = foundZipcode.a.string; #78201
            logging.debug("zipCode=%s", zipCode);
            
            gotZipCode = True;
        else:
            logging.debug("Failed for method 1, from %s", locationStr);
            gotZipCode = False;

    #Method 2: 
    #https://tools.usps.com/go/ZipLookupAction_input
    if(not gotZipCode):
        #https://tools.usps.com/go/ZipLookupAction.action
        zipLookupBaseUrl = "https://tools.usps.com/go/ZipLookupAction.action";
        #post data:
        #mode=0&tCompany=&tZip=&tAddress=&tApt=&tCity=WEST+PALM+BEACH&sState=FL&tUrbanCode=&zip=
        paraDict ={
            'mode'      : "0",
            'tCompany'  : "",
            'tZip'      : "",
            'tAddress'  : "",
            'tApt'      : "",
            'tCity'     : city,
            'sState'    : state,
            'tUrbanCode':"",
            "zip"       : "",
            
        };
        encodedPara = urllib.urlencode(paraDict);
        logging.debug("encodedPara=%s", encodedPara);
        zipLookupUrl = zipLookupBaseUrl + "?" + encodedPara;
        logging.debug("zipLookupUrl=%s", zipLookupUrl);
        
        headerDict = {
            'Referer'   : "https://tools.usps.com/go/ZipLookupAction_input",
        };
        zipLookupRespHtml = getUrlRespHtml(zipLookupUrl, headerDict=headerDict);
        #logging.debug("zipLookupRespHtml=%s", zipLookupRespHtml);
        #<span class="zip" style="">33401</span>
        soup = BeautifulSoup(zipLookupRespHtml);
        foundZip = soup.find(name="span", attrs={"class":"zip", "style":""});
        logging.debug("foundZip=%s", foundZip);
        if(foundZip):
            zipCode = foundZip.string; #33401
            logging.debug("zipCode=%s", zipCode);
        
            gotZipCode = True;
        else:
            logging.debug("Failed for method 2, from %s", locationStr);
            gotZipCode = False; 

    return zipCode;


################################################################################
# BeautifulSoup
################################################################################

#------------------------------------------------------------------------------
#remove specific tag[key]=value in soup contents (list of BeautifulSoup.Tag/BeautifulSoup.NavigableString)
# eg:
# (1)
# removeSoupContentsTagAttr(soupContents, "p", "class", "cc-lisence")
# to remove <p class="cc-lisence" style="line-height:180%;">......</p>, from
# [
# u'\n',
# <p class="cc-lisence" style="line-height:180%;">......</p>,
# u'\u5bf9......\u3002',
#  <p>跑题了。......我争取。</p>,
#  <br />,
#  u'\n',
#  <div class="clear"></div>,
# ]
# (2)
#contents = removeSoupContentsTagAttr(contents, "div", "class", "addfav", True);
# remove <div class="addfav">.....</div> from:
# [u'\n',
# <div class="postFooter">......</div>, 
# <div style="padding-left:2em">
    # ...
    # <div class="addfav">......</div>
    # ...
# </div>,
 # u'\n']
def removeSoupContentsTagAttr(soupContents, tagName, tagAttrKey, tagAttrVal="", recursive=False) :
    global gVal;

    #print "in removeSoupContentsClass";

    #print "[",gVal['currentLevel'],"] input tagName=",tagName," tagAttrKey=",tagAttrKey," tagAttrVal=",tagAttrVal;
    
    #logging.debug("[%d] input, %s[%s]=%s, soupContents:%s", gVal['currentLevel'],tagName,tagAttrKey,tagAttrVal, soupContents);
    #logging.debug("[%d] input, %s[%s]=%s", gVal['currentLevel'],tagName, tagAttrKey, tagAttrVal);
    
    filtedContents = [];
    for singleContent in soupContents:
        #logging.debug("current singleContent=%s",singleContent);
    
        #logging.info("singleContent=%s", singleContent);
        #print "type(singleContent)=",type(singleContent);
        #print "singleContent.__class__=",singleContent.__class__;
        #if(isinstance(singleContent, BeautifulSoup)):
        #if(BeautifulSoup.Tag == singleContent.__class__):
        #if(isinstance(singleContent, instance)):
        #if(isinstance(singleContent, BeautifulSoup.Tag)):
        if(isinstance(singleContent, Tag)):
            #print "isinstance true";
            
            #logging.debug("singleContent: name=%s, attrMap=%s, attrs=%s",singleContent.name, singleContent.attrMap, singleContent.attrs);
            # if( (singleContent.name == tagName)
                # and (singleContent.attrMap)
                # and (tagAttrKey in singleContent.attrMap)
                # and ( (tagAttrVal and (singleContent.attrMap[tagAttrKey]==tagAttrVal)) or (not tagAttrVal) ) ):
                # print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent;
                # #print "dir(singleContent)=",dir(singleContent);
                # logging.debug("found %s[%s]=%s in %s", tagName, tagAttrKey, tagAttrVal, singleContent.attrMap);

            # above using attrMap, but attrMap has bug for:
            #singleContent: name=script, attrMap=None, attrs=[(u'type', u'text/javascript'), (u'src', u'http://partner.googleadservices.com/gampad/google_service.js')]
            # so use attrs here
            #logging.debug("singleContent: name=%s, attrs=%s", singleContent.name, singleContent.attrs);
            attrsDict = tupleListToDict(singleContent.attrs);
            if( (singleContent.name == tagName)
                and (singleContent.attrs)
                and (tagAttrKey in attrsDict)
                and ( (tagAttrVal and (attrsDict[tagAttrKey]==tagAttrVal)) or (not tagAttrVal) ) ):
                #print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent;
                #print "dir(singleContent)=",dir(singleContent);
                logging.debug("found %s[%s]=%s in %s", tagName, tagAttrKey, tagAttrVal, attrsDict);
            else:
                if(recursive):
                    #print "-----sub call";
                    gVal['currentLevel'] = gVal['currentLevel'] + 1;
                    #logging.debug("[%d] now will filter %s[%s=]%s, for singleContent.contents=%s", gVal['currentLevel'], tagName,tagAttrKey,tagAttrVal, singleContent.contents);
                    #logging.debug("[%d] now will filter %s[%s=]%s", gVal['currentLevel'], tagName,tagAttrKey,tagAttrVal);
                    filteredSingleContent = singleContent;
                    filteredSubContentList = removeSoupContentsTagAttr(filteredSingleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive);
                    gVal['currentLevel'] = gVal['currentLevel'] -1;
                    filteredSingleContent.contents = filteredSubContentList;
                    #logging.debug("[%d] after filter, sub contents=%s", gVal['currentLevel'], filteredSingleContent);
                    #logging.debug("[%d] after filter contents", gVal['currentLevel']);
                    filtedContents.append(filteredSingleContent);
                else:
                    #logging.debug("not recursive, append:%s", singleContent);
                    #logging.debug("not recursive, now append singleContent");
                    filtedContents.append(singleContent);
            
            # name = singleContent.name;
            # if(name == tagName):
                # print "name is equal, name=",name;
                
                # attrMap = singleContent.attrMap;
                # print "attrMap=",attrMap;
                # if attrMap:
                    # if tagAttrKey in attrMap:
                        # print "tagAttrKey=",tagAttrKey," in attrMap";
                        # if(tagAttrVal and (attrMap[tagAttrKey]==tagAttrVal)) or (not tagAttrVal):
                            # print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent;
                            # #print "dir(singleContent)=",dir(singleContent);
                            # logging.debug("found tag, tagAttrVal=%s, %s[%s]=%s", tagAttrVal, tagName, tagAttrVal, attrMap[tagAttrKey]);
                        # else:
                            # print "key in attrMap, but value not equal";
                            # if(recursive):
                                # print "-----sub call 111";
                                # gVal['currentLevel'] = gVal['currentLevel'] + 1;
                                # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive);
                                # gVal['currentLevel'] = gVal['currentLevel'] -1;
                            # filtedContents.append(singleContent);
                    # else:
                        # print "key not in attrMap";
                        # if(recursive):
                            # print "-----sub call 222";
                            # gVal['currentLevel'] = gVal['currentLevel'] + 1;
                            # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive);
                            # gVal['currentLevel'] = gVal['currentLevel'] -1;
                        # filtedContents.append(singleContent);
                # else:
                    # print "attrMap is None";
                    # if(recursive):
                        # print "-----sub call 333";
                        # gVal['currentLevel'] = gVal['currentLevel'] + 1;
                        # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive);
                        # gVal['currentLevel'] = gVal['currentLevel'] -1;
                    # filtedContents.append(singleContent);
            # else:
                # print "name not equal, name=",name," tagName=",tagName;
                # if(recursive):
                    # print "-----sub call 444";
                    # gVal['currentLevel'] = gVal['currentLevel'] + 1;
                    # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive);
                    # gVal['currentLevel'] = gVal['currentLevel'] -1;
                # filtedContents.append(singleContent);
        else:
            # is BeautifulSoup.NavigableString
            #print "not BeautifulSoup instance";
            filtedContents.append(singleContent);

    #print "filterd contents=",filtedContents;
    #logging.debug("[%d] before return, filtedContents=%s", gVal['currentLevel'], filtedContents);
    
    return filtedContents;

#------------------------------------------------------------------------------
# convert soup contents into unicode string
def soupContentsToUnicode(soupContents) :
    #method 1
    mappedContents = map(CData, soupContents);
    #print "mappedContents OK";
    #print "type(mappedContents)=",type(mappedContents); #type(mappedContents)= <type 'list'>
    contentUni = ''.join(mappedContents);
    #print "contentUni=",contentUni;
    
    # #method 2
    # originBlogContent = "";
    # logging.debug("Total %d contents for original soup contents:", len(soupContents));
    # for i, content in enumerate(soupContents):
        # if(content):
            # logging.debug("[%d]=%s", i, content);
            # originBlogContent += unicode(content);
        # else :
            # logging.debug("[%d] is null", i);
    
    # logging.debug("---method 1: map and join---\n%s", contentUni);
    # logging.debug("---method 2: enumerate   ---\n%s", originBlogContent);
    
    # # -->> seem that two method got same blog content
    
    #logging.debug("soup contents to unicode string OK");
    return contentUni;

#------------------------------------------------------------------------------
# find the first BeautifulSoup.NavigableString from soup contents
def findFirstNavigableString(soupContents):
    firstString = None;
    for eachContent in soupContents:
        # note here must import NavigableString from BeautifulSoup
        if(isinstance(eachContent, NavigableString)): 
            firstString = eachContent;
            break;

    return firstString;


################################################################################
# Logging
################################################################################
def loggingInit(filename = None,
                fileLogLevel = logging.DEBUG,
                fileLogFormat = 'LINE %(lineno)-4d  %(levelname)-8s %(message)s',
                enableConsole = True,
                consoleLogLevel = logging.INFO,
                consoleLogFormat = "LINE %(lineno)-4d : %(levelname)-8s %(message)s",
                ):
    """
    init logging for both log to file and console

    :param logFilename: input log file name
        if not passed, use current script filename
    :return: none
    """
    curLogFilename = ""
    if filename:
        curLogFilename = filename
    else:
        curLogFilename = getInputFileBasenameNoSuffix()

    logging.basicConfig(
                    level    = fileLogLevel,
                    format   = fileLogFormat,
                    datefmt  = '%m-%d %H:%M',
                    filename = curLogFilename + ".log",
                    filemode = 'w')
    if enableConsole :
        # define a Handler which writes INFO messages or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(consoleLogLevel)
        # set a format which is simpler for console use
        formatter = logging.Formatter(consoleLogFormat)
        # tell the handler to use this format
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)


if __name__=="crifanLib":
    gVal['picSufChars'] = genSufList()
    #print "gVal['picSufChars']=",gVal['picSufChars']
    print "Imported: %s,\t%s"%( __name__, __VERSION__)