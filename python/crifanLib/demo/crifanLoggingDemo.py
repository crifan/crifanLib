import sys
import os
curFolder = os.path.abspath(__file__)
parentFolder = os.path.dirname(curFolder)
parentParentFolder = os.path.dirname(parentFolder)
# parentParentParentFolder = os.path.dirname(parentParentFolder)
sys.path.append(curFolder)
sys.path.append(parentFolder)
sys.path.append(parentParentFolder)
# sys.path.append(parentParentParentFolder)

from crifanLogging import loggingInit

import logging

def demoLoggingInit():
  loggingInit(
    "crifanLoggingDemo.log",
    # consoleLogFormat="%(asctime)s %(lineno)-4d %(levelname)-7s %(message)s"
  )
  logging.info("you can see this info in File and Console")
  # File crifanLoggingDemo.log:
  # 2018/12/01 09:55:01 crifanLoggingDemo.py:21   INFO    you can see this info in File and Console
  # Console:
  # 20181201 09:49:38 21   INFO    you can see this info in File and Console

if __name__ == "__main__":
  demoLoggingInit()
