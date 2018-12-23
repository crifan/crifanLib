import sys
import os
curFolder = os.path.abspath(__file__)
parentFolder = os.path.dirname(curFolder)
parentParentFolder = os.path.dirname(parentFolder)
parentParentParentFolder = os.path.dirname(parentParentFolder)
sys.path.append(curFolder)
sys.path.append(parentFolder)
sys.path.append(parentParentFolder)
sys.path.append(parentParentParentFolder)

import datetime
from crifanMultimedia import resizeImage

def testFilename():
  imageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day.png"
  outputImageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day_300x300.png"
  print("imageFilename=%s" % imageFilename)
  beforeTime = datetime.datetime.now()
  resizeImage(imageFilename, (300, 300), outputImageFile=outputImageFilename)
  afterTime = datetime.datetime.now()
  print("procesTime: %s" % (afterTime - beforeTime))

  outputImageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day_800x800.png"
  beforeTime = datetime.datetime.now()
  resizeImage(imageFilename, (800, 800), outputImageFile=outputImageFilename)
  afterTime = datetime.datetime.now()
  print("procesTime: %s" % (afterTime - beforeTime))


def testFileObject():
  imageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day.png"
  imageFileObj = open(imageFilename, "rb")
  outputImageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day_600x600.png"
  beforeTime = datetime.datetime.now()
  resizeImage(imageFileObj, (600, 600), outputImageFile=outputImageFilename)
  afterTime = datetime.datetime.now()
  print("procesTime: %s" % (afterTime - beforeTime))


def testBinaryBytes():
  imageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/take tomato.png"
  imageFileObj = open(imageFilename, "rb")
  imageBytes = imageFileObj.read()
  # return binary bytes
  beforeTime = datetime.datetime.now()
  resizedImageBytes = resizeImage(imageBytes, (800, 800))
  afterTime = datetime.datetime.now()
  print("procesTime: %s" % (afterTime - beforeTime))
  print("len(resizedImageBytes)=%s" % len(resizedImageBytes))

  # save to file
  outputImageFilename = "/Users/crifan/dev/tmp/python/resize_image_demo/hot day_750x750.png"
  beforeTime = datetime.datetime.now()
  resizeImage(imageBytes, (750, 750), outputImageFile=outputImageFilename)
  afterTime = datetime.datetime.now()
  print("procesTime: %s" % (afterTime - beforeTime))

  imageFileObj.close()


def demoResizeImage():
  testFilename()
  testFileObject()
  testBinaryBytes()

if __name__ == "__main__":
  demoResizeImage()

  # imageFilename=/Users/crifan/dev/tmp/python/resize_image_demo/hot day.png
  # procesTime: 0:00:00.619377
  # procesTime: 0:00:00.745228
  # procesTime: 0:00:00.606060
  # 1146667 -> 753258, resize ratio: 65%
  # procesTime: 0:00:00.773289
  # len(resizedImageBytes)=753258
  # procesTime: 0:00:00.738237