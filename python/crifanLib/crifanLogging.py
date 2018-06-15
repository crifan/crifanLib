#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanLogging.py
Function: crifanLib's logging related functions.
Version: v1.3 20180609
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.3"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import logging


################################################################################
# Config
################################################################################

LOG_FORMAT_FILE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
LOG_LEVEL_FILE = logging.DEBUG
LOG_FORMAT_CONSOLE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
LOG_LEVEL_CONSOLE = logging.INFO

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanLogging"

################################################################################
# Logging
################################################################################

def loggingInit(filename = None,
                fileLogLevel = LOG_LEVEL_FILE,
                fileLogFormat = LOG_FORMAT_FILE,
                fileLogDateFormat = '%Y/%m/%d %I:%M:%S',
                enableConsole = True,
                consoleLogLevel = LOG_LEVEL_CONSOLE,
                consoleLogFormat = LOG_FORMAT_CONSOLE,
                consoleLogDateFormat = '%Y%m%d %I:%M:%S',
                ):
    """
    init logging for both log to file and console

    :param logFilename: input log file name
        if not passed, use current lib filename
    :return: none
    """
    logFilename = ""
    if filename:
        logFilename = filename
    else:
        # logFilename = __file__ + ".log"
        # '/Users/crifan/dev/dev_root/company/naturling/projects/NLP/sourcecode/naturling/processData/mysqlQa/crifanLogging.py.log'
        logFilename = CURRENT_LIB_FILENAME + ".log"

    # logging.basicConfig(
    #                 level    = fileLogLevel,
    #                 format   = fileLogFormat,
    #                 datefmt  = fileLogDateFormat,
    #                 filename = logFilename,
    #                 encoding = "utf-8",
    #                 filemode = 'w')

    # rootLogger = logging.getLogger()
    rootLogger = logging.getLogger("")
    rootLogger.setLevel(fileLogLevel)
    fileHandler = logging.FileHandler(
        filename=logFilename,
        mode='w',
        encoding="utf-8")
    fileHandler.setLevel(fileLogLevel)
    fileFormatter = logging.Formatter(
        fmt=fileLogFormat,
        datefmt=fileLogDateFormat
    )
    fileHandler.setFormatter(fileFormatter)
    rootLogger.addHandler(fileHandler)

    if enableConsole :
        # define a Handler which writes INFO messages or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(consoleLogLevel)
        # set a format which is simpler for console use
        formatter = logging.Formatter(
            fmt=consoleLogFormat,
            datefmt=consoleLogDateFormat)
        # tell the handler to use this format
        console.setFormatter(formatter)
        rootLogger.addHandler(console)

################################################################################
# Test
################################################################################

def testLogging():
    loggingInit("testLogging.log")
    # loggingInit()

    logging.debug("log debug")
    logging.info("log info")
    logging.warning("log waring")
    logging.error("log error")
    logging.critical("log critical")
    logging.exception("log exception") # NoneType: None


if __name__ == '__main__':
    # print("[crifanLib-%s] %s" % (__file__, __version__))
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))

    testLogging()
