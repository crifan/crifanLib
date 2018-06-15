#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanEmail.py
Function: crifanLib's email related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


import logging
import smtplib
from email import encoders
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr


################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanEmail"

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
# Email Function
################################################################################


def formatEmailHeader(headerValue, encode="utf-8"):
    """
    format non-ASCII email header value to RFC 2822-compliant

    Example:
        u'绿色垃圾' -> =?utf-8?b?57u/6Imy5Z6D5Zy+?=

        u'Crifan2003 <crifan2003@163.com>, 克瑞芬 <admin@crifan.com>'
        ->
        =?utf-8?b?Q3JpZmFuMjAwMyA8Y3JpZmFuMjAwM0AxNjMuY29tPiwg5YWL55Ge6IqsIDxh?=
=?utf-8?q?dmin=40crifan=2Ecom=3E?=

    :param headerValue:
    :param encode:
    :return:
    """
    encodedHeaderValue = Header(headerValue, encode)
    return encodedHeaderValue

def formatEmailNameAddrHeader(nameAndAddress, encode="utf-8"):
    """

    Example:
        u'绿色垃圾 <green-waste@163.com>' -> '=?utf-8?b?57u/6Imy5Z6D5Zy+?= <green-waste@163.com>'

    :param nameAndAddress:
    :param encode:
    :return:
    """
    (nameUnicode, addrUnicode) = parseaddr(nameAndAddress)
    nameStr = nameUnicode.encode(encode) # '绿色垃圾'
    addrStr = addrUnicode.encode(encode) # 'green-waste@163.com'
    formatedNameHeaderUnicode = formatEmailHeader(nameStr)
    formatedNameHeaderStr = formatedNameHeaderUnicode.encode(encode) # =?utf-8?b?57u/6Imy5Z6D5Zy+?=
    formatedNameAndAddress = formataddr((formatedNameHeaderStr, addrStr)) # '=?utf-8?b?57u/6Imy5Z6D5Zy+?= <green-waste@163.com>'
    return formatedNameAndAddress

def sendEmail(  sender, senderPassword, receiverList,
                senderName="", receiverNameList= "",
                smtpServer = "", smtpPort = None, useSSL=False,
                type = "plain", title = "", body = ""):
    """
    send email
    :param sender:
    :param senderPassword:
    :param receiverList:
    :param senderName:
    :param receiverNameList:
    :param smtpServer:
    :param smtpPort:
    :param type: html/plain
    :param title:
    :param body:
    :return:
    """
    logging.debug("sender=%s, senderName=%s, smtpServer=%s, smtpPort=%s, useSSL=%s, type=%s, title=%s, body=%s",
                  sender, senderName, smtpServer, smtpPort, useSSL, type, title, body)
    logging.debug("receiverList=%s, receiverNameList=%s", receiverList, receiverNameList)

    defaultPort = None
    SMTP_PORT_NO_SSL = 25
    SMTP_PORT_SSL = 465
    if useSSL:
        defaultPort = SMTP_PORT_SSL
    else:
        defaultPort = SMTP_PORT_NO_SSL

    if not smtpPort:
        smtpPort = defaultPort

    # init smtp server if necessary
    if not smtpServer:
        # extract domain from sender email
        # crifan2003@163.com -> 163.com
        atIdx = sender.index('@')
        afterAtIdx = atIdx + 1
        lastDomain = sender[afterAtIdx:]
        smtpServer = 'smtp.' + lastDomain
        # smtpServer = "smtp.163.com"
        # smtpPort = 25

    # RECEIVER_SEPERATOR = '; '
    RECEIVER_SEPERATOR = ', '

    senderNameAddr = "%s <%s>" % (senderName, sender)
    receiversAddr = RECEIVER_SEPERATOR.join(receiverList)
    receiverNameAddrList = []
    formatedReceiverNameAddrList = []
    for curIdx, eachReceiver in enumerate(receiverList):
        eachReceiverName = receiverNameList[curIdx]
        eachNameAddr = "%s <%s>" % (eachReceiverName, eachReceiver)
        eachFormatedNameAddr = formatEmailNameAddrHeader(eachNameAddr)
        receiverNameAddrList.append(eachNameAddr)
        formatedReceiverNameAddrList.append(eachFormatedNameAddr)

    formatedReceiversNameAddr = RECEIVER_SEPERATOR.join(formatedReceiverNameAddrList) # '=?utf-8?b?57u/6Imy5Z6D5Zy+?= <green-waste@163.com>, =?utf-8?b?5YWL55Ge6Iqs?= <admin@crifan.com>'
    mergedReceiversNameAddr = RECEIVER_SEPERATOR.join(receiverNameAddrList) # u'Crifan2003 <crifan2003@163.com>, 克瑞芬 <admin@crifan.com>'
    # formatedReceiversNameAddr = formatEmailHeader(mergedReceiversNameAddr) #=?utf-8?b?Q3JpZmFuMjAwMyA8Y3JpZmFuMjAwM0AxNjMuY29tPiwg5YWL55Ge6IqsIDxh?=
    # =?utf-8?q?dmin=40crifan=2Ecom=3E?=

    msg = MIMEText(body, _subtype=type, _charset="utf-8")
    # msg["From"] = _format_addr(senderNameAddr)
    # msg["To"] = _format_addr(receiversNameAddr)
    msg["From"] = formatEmailHeader(senderNameAddr)
    # msg["From"] = senderNameAddr
    # msg["To"] = formatEmailHeader(formatedReceiversNameAddr)
    # msg["To"] = formatedReceiversNameAddr
    # msg["To"] = mergedReceiversNameAddr
    # msg["To"] = formatEmailHeader(receiversAddr)
    msg["To"] = formatEmailHeader(mergedReceiversNameAddr)
    # titleHeader = Header(title, "utf-8")
    # encodedTitleHeader = titleHeader.encode()
    # msg['Subject'] = encodedTitleHeader
    msg['Subject'] = formatEmailHeader(title)
    # msg['Subject'] = title
    msgStr = msg.as_string()

    # try:
    # smtpObj = smtplib.SMTP('localhost')
    smtpObj = None
    if useSSL:
        smtpObj = smtplib.SMTP_SSL(smtpServer, smtpPort)
    else:
        smtpObj = smtplib.SMTP(smtpServer, smtpPort)
        # start TLS for security
        # smtpObj.starttls()
    # smtpObj.set_debuglevel(1)
    smtpObj.login(sender, senderPassword)
    # smtpObj.sendmail(sender, receiversAddr, msgStr)
    smtpObj.sendmail(sender, receiverList, msgStr)
    logging.info("Successfully sent email: message=%s", msgStr)
    # except smtplib.SMTPException:
    #     logging.error("Fail to sent email: message=%s", message)

    return

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))