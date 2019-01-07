#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanFlask.py
Function: crifanLib's Flask related functions.
Version: v20181224
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v20190107"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import io
from flask import send_file

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanFlask"

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
# Flask Function
################################################################################


def sendFile(fileBytes, contentType, outputFilename, asAttachment=True):
    """
        flask return downloadable file or file's binary stream data
            example url: http://127.0.0.1:34800/audio/5c1c631c127588257d568eba/3569.mp3
    :param fileBytes:  file binary bytes
    :param contentType: MIME content type, eg: audio/mpeg
    :param outputFilename: output filename, eg: 3569.mp3
    :param asAttachment: True to return downloable file with filename, False to return binary stream file data
    :return: Flask response
    """
    """Flask API use this to send out file (to browser, browser can directly download file)"""
    # print("sendFile: len(fileBytes)=%s, contentType=%s, outputFilename=%s" % (len(fileBytes), contentType, outputFilename))
    # return send_file(
    #     io.BytesIO(fileBytes),
    #     mimetype=contentType,
    #     as_attachment=asAttachment,
    #     attachment_filename=outputFilename
    # )
    fileLength = len(fileBytes)
    responseFile = send_file(
        io.BytesIO(fileBytes),
        mimetype=contentType,
        as_attachment=asAttachment,
        attachment_filename=outputFilename
    )
    # add Content-Length to support miniprogram iOS background play audio works, not error: 10003
    responseFile.headers["Content-Length"] = fileLength
    return responseFile


################################################################################
# Test
################################################################################

def testSendFile():
    # inside flask api
    fileBytes = open("some_image.jpg", "rb")
    contentType = "image/jpeg"
    outputFilename = "output_image.jpg"

    fileBytes = open("some_audio.mp3", "rb")
    contentType = "audio/mpeg"
    outputFilename = "output_audio.mp3"

    return sendFile(fileBytes, contentType, outputFilename)


if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))
    # testSendFile()