#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanOpenpyxl.py
Function: crifanLib's openpyxl related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import logging

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanOpenpyxl"

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
# Openpyxl Function
################################################################################


def isInCellRange(cellToCheck, cellRange):
    """
    to check a cell whether in a cell range
    :param cellToCheck:
    :param cellRange:
    :return:
        True : if cell in range
        False: if cell not in range
    """
    # logging.debug("cellToCheck=[%d:%d]", cellToCheck.row, cellToCheck.col_idx)
    # logging.debug("cellRange: row=[%d:%d] col=[%d:%d]",
    #              cellRange.min_row, cellRange.max_row, cellRange.min_col, cellRange.max_col)
    if (cellToCheck.row >= cellRange.min_row) and \
        (cellToCheck.row <= cellRange.max_row) and \
        (cellToCheck.col_idx >= cellRange.min_col) and \
        (cellToCheck.col_idx <= cellRange.max_col):
        logging.info("cell[%d:%d] with in cell range: row=[%d:%d] col=[%d:%d]",
                     cellToCheck.row, cellToCheck.col_idx,
                     cellRange.min_row, cellRange.max_row, cellRange.min_col, cellRange.max_col)
        return True
    else:
        return False


def getCellRangeValue(ws, cellRange):
    """
    get cell range value -> the top left cell value
    :param cellRange:
    :return:
    """
    topLeftCell = ws.cell(row=cellRange.min_row, column=cellRange.min_col)
    topLeftCellValue = topLeftCell.value
    return topLeftCellValue

def getRealCellValue(ws, curCell):
    """
    for openpyxl, to get real value from row and column
    expecially for merged cell, will get its (same) value from top-left cell value

    :param curCell:
    :return:
        ("some normal value", None)
        ("some real value from range", <CellRange N146:N163>)
    """

    withinCellRange = None

    realCellValue = curCell.value

    mergedCellsRangesList = ws.merged_cells.ranges
    # logging.info("mergedCellsRangesList=%s", mergedCellsRangesList)

    # Note:
    # to efficiency , we only check cell in range or not when its value is None
    # for all merged cell value is None
    if not realCellValue:
        for eachCellRange in mergedCellsRangesList:
            if isInCellRange(curCell, eachCellRange):
                # logging.info("mergedCellsRangesList=%s", mergedCellsRangesList)
                cellRangeValue = getCellRangeValue(ws, eachCellRange)
                realCellValue = cellRangeValue
                withinCellRange = eachCellRange
                logging.info("withinCellRange=%s", withinCellRange)
                break

    return realCellValue, withinCellRange

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))