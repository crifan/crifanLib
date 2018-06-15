#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanHtml.py
Function: crifanLib's html related functions.
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

try:
    import htmlentitydefs
except ImportError:
    # possible python 3
    try:
        import html.entities as htmlentitydefs
    except:
        print("crifanHtml: Can not found html.entities or htmlentitydefs lib")

# from . import crifanSystem
import crifanLib.crifanSystem

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanHtml"

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
# HTML Function
################################################################################


################################################################################
# HTML
################################################################################

def codePointToChar(codePoint):
    """convert unicode code point to char"""
    unicodeChar = ""
    if crifanLib.crifanSystem.isPython2():
        unicodeChar = unichr(codePoint)
    else:
        unicodeChar = chr(codePoint)

    return unicodeChar

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
    decodedHtml = ""

    # A dictionary mapping XHTML 1.0 entity definitions to their replacement text in ISO Latin-1
    # 'zwnj': '&#8204;',
    # 'aring': '\xe5',
    # 'gt': '>',
    # 'yen': '\xa5',
    # logging.debug("htmlentitydefs.entitydefs=%s", htmlentitydefs.entitydefs);

    # A dictionary that maps HTML entity names to the Unicode codepoints
    # 'aring': 229,
    # 'gt': 62,
    # 'sup': 8835,
    # 'Ntilde': 209,
    # logging.debug("htmlentitydefs.name2codepoint=%s", htmlentitydefs.name2codepoint);

    # A dictionary that maps Unicode codepoints to HTML entity names
    # 8704: 'forall',
    # 8194: 'ensp',
    # 8195: 'emsp',
    # 8709: 'empty',
    # logging.debug("htmlentitydefs.codepoint2name=%s", htmlentitydefs.codepoint2name);

    # http://fredericiana.com/2010/10/08/decoding-html-entities-to-text-in-python/
    # http://autoexplosion.com/RVs/buy/9882.php
    # will error
    # not support key : Dryer
    # when use:
    # decodedEntityName = re.sub('&(?P<entityName>[a-zA-Z]{2,10});', lambda matched: unichr(htmlentitydefs.name2codepoint[matched.group("entityName")]), origHtml);

    # logging.debug("origHtml=%s", origHtml)
    def _nameToCodepoint(matched):
        # logging.debug("matched=%s", matched)
        wholeStr = matched.group(0)
        # logging.debug("wholeStr=%s", wholeStr)
        decodedUnicodeChar = ""
        entityName = matched.group("entityName")
        # logging.debug("entityName=%s", entityName)
        if (entityName in htmlentitydefs.name2codepoint):
            decodedCodepoint = htmlentitydefs.name2codepoint[entityName]
            # logging.debug("decodedCodepoint=%s", decodedCodepoint)
            decodedUnicodeChar = codePointToChar(decodedCodepoint)
        else:
            # invalid key, just omit it

            # http://autoexplosion.com/RVs/buy/9882.php
            # &Dryer;
            # from
            # Washer&Dryer;, Awning,
            decodedUnicodeChar = wholeStr
        # logging.debug("decodedUnicodeChar=%s", decodedUnicodeChar)
        return decodedUnicodeChar

    decodedEntityName = re.sub('&(?P<entityName>[a-zA-Z]{2,10});', _nameToCodepoint, origHtml);
    # logging.info("decodedEntityName=%s", decodedEntityName);

    # print "type(decodedEntityName)=",type(decodedEntityName); #type(decodedEntityName)= <type 'unicode'>
    decodedCodepointInt = re.sub('&#(?P<codePointInt>\d{2,5});',
                                 lambda matched: codePointToChar(int(matched.group("codePointInt"))), decodedEntityName)
    # print "decodedCodepointInt=",decodedCodepointInt
    decodedCodepointHex = re.sub('&#x(?P<codePointHex>[a-fA-F\d]{2,5});',
                                 lambda matched: codePointToChar(int(matched.group("codePointHex"), 16)),
                                 decodedCodepointInt)
    # print "decodedCodepointHex=",decodedCodepointHex

    # logging.info("origHtml=%s", origHtml);
    decodedHtml = decodedCodepointHex
    # logging.info("decodedHtml=%s", decodedHtml); #type(decodedHtml)= <type 'unicode'>

    # here mabye is unicode string
    if (decodedEncoding):
        # note: here decodedhtml is unicode
        decodedhtml = decodedHtml.encode(decodedEncoding, 'ignore')
        # print "after encode into decodedEncoding=%s, decodedhtml=%s"%(decodedEncoding, decodedhtml);

    return decodedHtml


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
    nameToCodepointDict = {}
    for eachName in htmlentitydefs.name2codepoint:
        fullName = "&" + eachName + ";"
        fullCodepoint = "&#" + str(htmlentitydefs.name2codepoint[eachName]) + ";"
        nameToCodepointDict[fullName] = fullCodepoint

    # "&aring;" -> "&#229;"
    htmlWithCodepoint = htmlWithEntityName
    for key in nameToCodepointDict.keys():
        htmlWithCodepoint = re.compile(key).sub(nameToCodepointDict[key], htmlWithCodepoint)
    return htmlWithCodepoint


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
    codepointToNameDict = {}
    for eachCodepoint in htmlentitydefs.codepoint2name:
        fullCodepoint = "&#" + str(eachCodepoint) + ";"
        fullName = "&" + htmlentitydefs.codepoint2name[eachCodepoint] + ";"
        codepointToNameDict[fullCodepoint] = fullName

    # "&#160;" -> "&nbsp;"
    htmlWithEntityName = htmlWithCodepoint
    for key in codepointToNameDict.keys():
        htmlWithEntityName = re.compile(key).sub(codepointToNameDict[key], htmlWithEntityName)
    return htmlWithEntityName


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
    # logging.info("html tag, origHtml=%s", origHtml);
    filteredHtml = origHtml

    # Method 1: auto remove tag use re
    # remove br
    filteredHtml = re.sub("<br\s*>", "", filteredHtml, flags=re.I)
    filteredHtml = re.sub("<br\s*/>", "", filteredHtml, flags=re.I)
    # logging.info("remove br, filteredHtml=%s", filteredHtml)
    # remove a
    filteredHtml = re.sub("<a\s+[^<>]+>(?P<aContent>[^<>]+?)</a>", "\g<aContent>", filteredHtml, flags=re.I)
    # logging.info("remove a, filteredHtml=%s", filteredHtml)
    # remove b,strong
    filteredHtml = re.sub("<b>(?P<bContent>[^<>]+?)</b>", "\g<bContent>", filteredHtml, re.I)
    filteredHtml = re.sub("<strong>(?P<strongContent>[^<>]+?)</strong>", "\g<strongContent>", filteredHtml, flags=re.I)
    # logging.info("remove b,strong, filteredHtml=%s", filteredHtml)

    return filteredHtml


def repUniNumEntToChar(text):
    """
        replace the &#N; (N is digit number, N > 1) to unicode char
        eg:
            replace "&amp;#39;" with "'" in "Creepin&#39; up on you"
    :param text:
    :return:
    """
    unicodeP = re.compile('&#[0-9]+;')
    def transToUniChr(match): # translate the matched string to unicode char
        numStr = match.group(0)[2:-1] # remove '&#' and ';'
        num = int(numStr)
        unicodeChar = codePointToChar(num)
        return unicodeChar
    return unicodeP.sub(transToUniChr, text)

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))