#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanBeautifulSoup.py
Function: crifanLib's BeautifulSoup related functions.
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
    from BeautifulSoup import BeautifulSoup, Tag, CData, NavigableString
except ImportError:
    print("crifanBeautifulSoup: Can not found lib BeautifulSoup")

# from . import crifanList
import crifanLib.crifanList

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanBeautifulSoup"

################################################################################
# Global Variable
################################################################################
gVal = {
    'currentLevel': 0
}

gConst = {
}

################################################################################
# Internal Function
################################################################################


################################################################################
# BeautifulSoup Function
################################################################################


################################################################################
# BeautifulSoup
################################################################################


def removeSoupContentsTagAttr(soupContents, tagName, tagAttrKey, tagAttrVal="", recursive=False):
    """
        remove specific tag[key]=value in soup contents (list of BeautifulSoup.Tag/BeautifulSoup.NavigableString)
        eg:
        (1)
        removeSoupContentsTagAttr(soupContents, "p", "class", "cc-lisence")
        to remove <p class="cc-lisence" style="line-height:180%;">......</p>, from
        [
        u'\n',
        <p class="cc-lisence" style="line-height:180%;">......</p>,
        u'\u5bf9......\u3002',
         <p>跑题了。......我争取。</p>,
         <br />,
         u'\n',
         <div class="clear"></div>,
        ]
        (2)
        contents = removeSoupContentsTagAttr(contents, "div", "class", "addfav", True);
        remove <div class="addfav">.....</div> from:
        [u'\n',
        <div class="postFooter">......</div>,
        <div style="padding-left:2em">
        ...
        <div class="addfav">......</div>
        ...
        </div>,
        u'\n']
    :param soupContents:
    :param tagName:
    :param tagAttrKey:
    :param tagAttrVal:
    :param recursive:
    :return:
    """
    global gVal

    # print "in removeSoupContentsClass"
    # print "[",gVal['currentLevel'],"] input tagName=",tagName," tagAttrKey=",tagAttrKey," tagAttrVal=",tagAttrVal
    # logging.debug("[%d] input, %s[%s]=%s, soupContents:%s", gVal['currentLevel'],tagName,tagAttrKey,tagAttrVal, soupContents)
    # logging.debug("[%d] input, %s[%s]=%s", gVal['currentLevel'],tagName, tagAttrKey, tagAttrVal)

    filtedContents = []
    for singleContent in soupContents:
        # logging.debug("current singleContent=%s",singleContent)

        # logging.info("singleContent=%s", singleContent)
        # print "type(singleContent)=",type(singleContent)
        # print "singleContent.__class__=",singleContent.__class__
        # if(isinstance(singleContent, BeautifulSoup)):
        # if(BeautifulSoup.Tag == singleContent.__class__):
        # if(isinstance(singleContent, instance)):
        # if(isinstance(singleContent, BeautifulSoup.Tag)):
        if (isinstance(singleContent, Tag)):
            # print "isinstance true"

            # logging.debug("singleContent: name=%s, attrMap=%s, attrs=%s",singleContent.name, singleContent.attrMap, singleContent.attrs)
            # if( (singleContent.name == tagName)
            # and (singleContent.attrMap)
            # and (tagAttrKey in singleContent.attrMap)
            # and ( (tagAttrVal and (singleContent.attrMap[tagAttrKey]==tagAttrVal)) or (not tagAttrVal) ) ):
            # print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent
            # #print "dir(singleContent)=",dir(singleContent)
            # logging.debug("found %s[%s]=%s in %s", tagName, tagAttrKey, tagAttrVal, singleContent.attrMap)

            # above using attrMap, but attrMap has bug for:
            # singleContent: name=script, attrMap=None, attrs=[(u'type', u'text/javascript'), (u'src', u'http://partner.googleadservices.com/gampad/google_service.js')]
            # so use attrs here
            # logging.debug("singleContent: name=%s, attrs=%s", singleContent.name, singleContent.attrs)
            attrsDict = crifanList.tupleListToDict(singleContent.attrs)
            if ((singleContent.name == tagName)
                    and (singleContent.attrs)
                    and (tagAttrKey in attrsDict)
                    and ((tagAttrVal and (attrsDict[tagAttrKey] == tagAttrVal)) or (not tagAttrVal))):
                # print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent
                # print "dir(singleContent)=",dir(singleContent)
                # logging.debug("found %s[%s]=%s in %s", tagName, tagAttrKey, tagAttrVal, attrsDict)
                print("found %s[%s]=%s in %s" % (tagName, tagAttrKey, tagAttrVal, attrsDict))
            else:
                if (recursive):
                    # print "-----sub call"
                    gVal['currentLevel'] = gVal['currentLevel'] + 1
                    # logging.debug("[%d] now will filter %s[%s=]%s, for singleContent.contents=%s", gVal['currentLevel'], tagName,tagAttrKey,tagAttrVal, singleContent.contents)
                    # logging.debug("[%d] now will filter %s[%s=]%s", gVal['currentLevel'], tagName,tagAttrKey,tagAttrVal)
                    filteredSingleContent = singleContent
                    filteredSubContentList = removeSoupContentsTagAttr(filteredSingleContent.contents, tagName,
                                                                       tagAttrKey, tagAttrVal, recursive)
                    gVal['currentLevel'] = gVal['currentLevel'] - 1
                    filteredSingleContent.contents = filteredSubContentList
                    # logging.debug("[%d] after filter, sub contents=%s", gVal['currentLevel'], filteredSingleContent)
                    # logging.debug("[%d] after filter contents", gVal['currentLevel'])
                    filtedContents.append(filteredSingleContent)
                else:
                    # logging.debug("not recursive, append:%s", singleContent)
                    # logging.debug("not recursive, now append singleContent")
                    filtedContents.append(singleContent)

            # name = singleContent.name
            # if(name == tagName):
            # print "name is equal, name=",name

            # attrMap = singleContent.attrMap
            # print "attrMap=",attrMap
            # if attrMap:
            # if tagAttrKey in attrMap:
            # print "tagAttrKey=",tagAttrKey," in attrMap"
            # if(tagAttrVal and (attrMap[tagAttrKey]==tagAttrVal)) or (not tagAttrVal):
            # print "++++++++found tag:",tagName,"[",tagAttrKey,"]=",tagAttrVal,"\n in:",singleContent
            # #print "dir(singleContent)=",dir(singleContent)
            # logging.debug("found tag, tagAttrVal=%s, %s[%s]=%s", tagAttrVal, tagName, tagAttrVal, attrMap[tagAttrKey])
            # else:
            # print "key in attrMap, but value not equal"
            # if(recursive):
            # print "-----sub call 111"
            # gVal['currentLevel'] = gVal['currentLevel'] + 1
            # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive)
            # gVal['currentLevel'] = gVal['currentLevel'] -1
            # filtedContents.append(singleContent)
            # else:
            # print "key not in attrMap"
            # if(recursive):
            # print "-----sub call 222"
            # gVal['currentLevel'] = gVal['currentLevel'] + 1
            # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive)
            # gVal['currentLevel'] = gVal['currentLevel'] -1
            # filtedContents.append(singleContent)
            # else:
            # print "attrMap is None"
            # if(recursive):
            # print "-----sub call 333"
            # gVal['currentLevel'] = gVal['currentLevel'] + 1
            # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive)
            # gVal['currentLevel'] = gVal['currentLevel'] -1
            # filtedContents.append(singleContent)
            # else:
            # print "name not equal, name=",name," tagName=",tagName
            # if(recursive):
            # print "-----sub call 444"
            # gVal['currentLevel'] = gVal['currentLevel'] + 1
            # singleContent = removeSoupContentsTagAttr(singleContent.contents, tagName, tagAttrKey, tagAttrVal, recursive)
            # gVal['currentLevel'] = gVal['currentLevel'] -1
            # filtedContents.append(singleContent)
        else:
            # is BeautifulSoup.NavigableString
            # print "not BeautifulSoup instance"
            filtedContents.append(singleContent)

    # print "filterd contents=",filtedContents
    # logging.debug("[%d] before return, filtedContents=%s", gVal['currentLevel'], filtedContents)

    return filtedContents


def soupContentsToUnicode(soupContents):
    """convert soup contents into unicode string"""
    # method 1
    mappedContents = map(CData, soupContents)
    # print "mappedContents OK"
    # print "type(mappedContents)=",type(mappedContents) #type(mappedContents)= <type 'list'>
    contentUni = ''.join(mappedContents)
    # print "contentUni=",contentUni

    # #method 2
    # originBlogContent = ""
    # logging.debug("Total %d contents for original soup contents:", len(soupContents))
    # for i, content in enumerate(soupContents):
    # if(content):
    # logging.debug("[%d]=%s", i, content)
    # originBlogContent += unicode(content)
    # else :
    # logging.debug("[%d] is null", i)

    # logging.debug("---method 1: map and join---\n%s", contentUni)
    # logging.debug("---method 2: enumerate   ---\n%s", originBlogContent)

    # # -->> seem that two method got same blog content

    # logging.debug("soup contents to unicode string OK")
    return contentUni


def findFirstNavigableString(soupContents):
    """find the first BeautifulSoup.NavigableString from soup contents"""
    firstString = None
    for eachContent in soupContents:
        # note here must import NavigableString from BeautifulSoup
        if (isinstance(eachContent, NavigableString)):
            firstString = eachContent
            break

    return firstString


################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))