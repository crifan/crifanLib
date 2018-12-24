#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanMongodb.py
Function: crifanLib's Mongodb related functions.
Version: v20181224
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v20181224"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"


from flask import jsonify
from bson.objectid import ObjectId

from crifanLib.crifanFlask import sendFile

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanMongodb"

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
# Mongodb Function
################################################################################


def getGridfsFile(curGridfs, fileId, fileName=None, filterDataFunc=None):
    """
        generate downloadable gridfs file
    :param curGridfs: current gridfs collection
    :param fileId: mongodb gridfs file id
    :param fileName: filename
    :param filterDataFunc: before return file, filter data, such as reduce image size
    :return:
        gridfs file, support api caller(browser) to download file
    """
    # print("getGridfsFile: curGridfs=%s, fileId=%s, fileName=%s, filterDataFunc=%s" %
    #       (curGridfs, fileId, fileName, filterDataFunc))
    # curGridfs=<gridfs.GridFS object at 0x104c5d748>, fileId=5c1c6322127588257d56935e, fileName=vedio game.png, filterDataFunc=<function compressImageSize at 0x104f6e2f0>

    fileIdObj = ObjectId(fileId)
    # print("fileIdObj=%s" % fileIdObj)
    if not curGridfs.exists({"_id": fileIdObj}):
        respDict = {
            "code": 404,
            "message": "Not found gridfs file from id %s" % fileId,
            "data": {}
        }
        return jsonify(respDict)

    fileObj = curGridfs.get(fileIdObj)
    # print("fileObj=%s, filename=%s, chunkSize=%s, length=%s, contentType=%s" %
    #       (fileObj, fileObj.filename, fileObj.chunk_size, fileObj.length, fileObj.content_type))
    # print("lengthInMB=%.2f MB" % float(fileObj.length / (1024 * 1024)))

    fileBytes = fileObj.read()
    # print("len(fileBytes)=%s" % len(fileBytes))

    if filterDataFunc:
        fileBytes = filterDataFunc(fileBytes)
        # print("after process: len(fileBytes)=%s" % len(fileBytes))

    outputFilename = fileObj.filename
    if fileName:
        outputFilename = fileName
    # print("outputFilename=%s" % outputFilename)

    return sendFile(fileBytes, fileObj.content_type, outputFilename)


################################################################################
# Test
################################################################################


def compressImageSize(fileBytes):
    from crifanMultimedia import resizeImage
    IMAGE_COMPRESS_SIZE = (600, 600)
    return resizeImage(fileBytes, IMAGE_COMPRESS_SIZE)

def testGetGridfsFile():
    fileId = "5c1c631e127588257d568ebd"
    fileName = "rabbit.png"
    if fileType == "image":
        return getGridfsFile(mongoGridfs, fileId, fileName, compressImageSize)
    else:
        return getGridfsFile(mongoGridfs, fileId, fileName)

if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))
    # testGetGridfsFile()