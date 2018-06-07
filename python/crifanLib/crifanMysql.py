#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanMysql.py
Function: crifanLib's mysql related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/

  If you want to modify to your mysql and table, you need:
  (1) change change MysqlDb config to your mysql config
  (2) change CurrentTableName to your table name
  (3) change CreateTableSqlTemplate to your sql to create new mysql table fields
  (4) if your table field contain more type, edit insert to add more type for "TODO: add more type formatting if necessary"
"""


__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import logging
import re
import pymysql
import pymysql.cursors

################################################################################
# Config
################################################################################


CurrentTableName = "tbl_autohome_car_info"
CreateTableSqlTemplate = """CREATE TABLE IF NOT EXISTS `%s` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增，主键',
  `cityDealerPrice` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '经销商参考价',
  `msrpPrice` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '厂商指导价',
  `mainBrand` char(20) NOT NULL DEFAULT '' COMMENT '品牌',
  `subBrand` varchar(20) NOT NULL DEFAULT '' COMMENT '子品牌',
  `brandSerie` varchar(20) NOT NULL DEFAULT '' COMMENT '车系',
  `brandSerieId` varchar(15) NOT NULL DEFAULT '' COMMENT '车系ID',
  `model` varchar(50) NOT NULL DEFAULT '' COMMENT '车型',
  `modelId` varchar(15) NOT NULL DEFAULT '' COMMENT '车型ID',
  `modelStatus` char(5) NOT NULL DEFAULT '' COMMENT '车型状态',
  `url` varchar(200) NOT NULL DEFAULT '' COMMENT '车型url',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;"""

MysqlConfig = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': 'crifan_mysql',
    'database': 'AutohomeResultdb',
    'charset': "utf8"
}

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanMysql"

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
# Mysql Function
################################################################################


class MysqlDb:

    config = {}
    curTableName = ""
    createTableSqlTemplate = ""

    connection = None
    isConnected = False

    def __init__(self,
                 config=MysqlConfig,
                 needCreateTable=False,
                 tableName = CurrentTableName,
                 createTableSqlTemplate=CreateTableSqlTemplate):
        """
            init mysql
            for tablename:
                for needCreateTable=True, use db name if db in config
                otherwise use tableName parameter
        """
        logging.info("config=%s, needCreateTable=%s, tableName=%s, createTableSqlTemplate=%s",
                     config, needCreateTable, tableName, createTableSqlTemplate)

        self.config = config
        if 'db' in self.config:
            self.curTableName = self.config['db']
        else:
            self.curTableName = tableName

        self.createTableSqlTemplate = createTableSqlTemplate

        # 1. connect db first
        if self.connection is None:
            self.isConnected = self.connect()
            logging.info("Connect mysql return %s", self.isConnected)

        if self.isConnected:
            if needCreateTable:
                # 2. create table for db
                createTableOk, errDict = self.createTable(self.curTableName)
                logging.info("Create table %s return %s, %s", self.curTableName, createTableOk, errDict)

    def close(self):
        """close mysql connection"""
        if self.connection:
            self.connection.close()
            self.isConnected = False

    def connect(self):
        try:
            # self.connection = pymysql.connect(**self.config, cursorclass=pymysql.cursors.DictCursor)
            # self.connection = pymysql.connect(self.config, cursorclass=pymysql.cursors.DictCursor)
            self.config["cursorclass"] = pymysql.cursors.DictCursor
            self.connection = pymysql.connect(**self.config)
            logging.info("Connect mysql ok, self.connection=%s", self.connection)
            return True
        except pymysql.Error as err:
            logging.info("Connect mysql with config=%s, error=%s", self.config, err)
            return False

    def quoteIdentifier(self, identifier):
        """
            for mysql, it better to quote identifier xxx using backticks to `xxx`
            in case, identifier:
                contain special char, such as space
                or same with system reserved words, like select
        """
        quotedIdentifier = "`%s`" % identifier
        # logging.info("quotedIdentifier=", quotedIdentifier)
        return quotedIdentifier

    def extractMysqlErrorCodeMessage(self, mysqlErrorStr):
        """extract mysql error code from error string"""
        # (1062, "Duplicate entry 'Here you go.-Thank you very much.' for key 'Q+A'")
        foundErrorCode, errorCode, errorMessage = False, 0, "Unknown Error"
        mysqlErrorCodeMatch = re.search('^\((?P<mysqlErrorCode>\d+),\s*["|\'](?P<errorMessage>.+?)["|\']\)$', mysqlErrorStr)
        if mysqlErrorCodeMatch:
            foundErrorCode = True
            mysqlErrorCode = mysqlErrorCodeMatch.group("mysqlErrorCode")
            mysqlErrorCodeInt = int(mysqlErrorCode)
            errorCode = mysqlErrorCodeInt
            errorMessage = mysqlErrorCodeMatch.group("errorMessage")
        else:
            logging.error("Unrecognized mysql error: %s", mysqlErrorStr)

        return foundErrorCode, errorCode, errorMessage
    #
    # def isMysqlSyntaxError(self, mysqlErrStr):
    #     """check whether is mysql syntax error from error string"""
    #     # (1064, 'You have an error in your SQL syntax; ...
    #     isSyntaxError = False
    #
    #     foundErrorCode, errorCode = self.extractMysqlErrorCode(mysqlErrStr)
    #     if foundErrorCode:
    #         if errorCode == 1064:
    #             isSyntaxError = True
    #
    #     return isSyntaxError
    #
    # def isMysqlDuplicateError(self, mysqlErrStr):
    #     """check whether is mysql duplicate error from error string"""
    #     # 1062, "Duplicate entry 'Here you go.-T...
    #     isDupError = False
    #
    #     foundErrorCode, errorCode = self.extractMysqlErrorCode(mysqlErrStr)
    #     if foundErrorCode:
    #         if errorCode == 1062:
    #             isDupError = True
    #
    #     return isDupError

    def executeSql(self, sqlStr, actionDescription=""):
        logging.debug("executeSql: sqlStr=%s, actionDescription=%s", sqlStr, actionDescription)

        executeOk = False
        errDict = {
            "code": 0,
            "message": "Unknown Mysql Error"
        }

        if self.connection is None:
            logging.error("Please connect mysql first before %s", actionDescription)
            executeOk = False
            errDict["code"] = 10000
            errDict["message"] = "Mysql not connected"
            return executeOk, errDict

        cursor = self.connection.cursor()
        logging.debug("cursor=%s", cursor)

        try:
            cursor.execute(sqlStr)
            self.connection.commit()
            logging.debug("+++ Ok to execute sql %s for %s", sqlStr, actionDescription)
            executeOk = True
        except pymysql.Error as err:
            errStr = str(err)

            # logging.error("!!! %s when execute sql: %s for %s", errStr, sqlStr, actionDescription)
            logging.debug("!!! %s when execute sql: %s for %s", errStr, sqlStr, actionDescription)
            self.connection.rollback()

            executeOk = False
            foundErrorCode, errorCode, errorMessage = self.extractMysqlErrorCodeMessage(errStr)
            if foundErrorCode:
                errDict = {
                    "code": errorCode,
                    "message": errorMessage
                }

        return executeOk, errDict

    def createTable(self, newTablename):
        logging.info("createTable: newTablename=%s", newTablename)

        createTableSql = self.createTableSqlTemplate % (newTablename)
        logging.info("createTableSql=%s", createTableSql)

        return self.executeSql(sqlStr=createTableSql, actionDescription=("Create table %s" % newTablename))

    def dropTable(self, existedTablename):
        logging.info("dropTable: existedTablename=%s", existedTablename)

        dropTableSql = "DROP TABLE IF EXISTS %s" % (existedTablename)
        logging.info("dropTableSql=%s", dropTableSql)

        return self.executeSql(sqlStr=dropTableSql, actionDescription=("Drop table %s" % existedTablename))

    # def insert(self, **valueDict):
    def insert(self, valueDict, tablename=curTableName):
        """
            inset dict value into mysql table
            makesure the value is dict, and its keys is the key in the table
        """
        logging.info("insert: valueDict=%s, tablename=%s", valueDict, tablename)

        dictKeyList = valueDict.keys()
        dictValueList = valueDict.values()
        logging.info("dictKeyList=%s, dictValueList=%s", dictKeyList, dictValueList)

        keyListSql = ", ".join(self.quoteIdentifier(eachKey) for eachKey in dictKeyList)
        logging.info("keyListSql=%s", keyListSql)
        # valueListSql = ", ".join(eachValue for eachValue in dictValueList)
        valueListSql = ""
        formattedDictValueList = []
        for eachValue in dictValueList:
            # logging.info("eachValue=", eachValue)
            eachValueInSql = ""
            valueType = type(eachValue)
            # logging.info("valueType=", valueType)
            if valueType is str:
                eachValueInSql = '"%s"' % eachValue
            elif valueType is int:
                eachValueInSql = '%d' % eachValue
            # TODO: add more type formatting if necessary
            logging.info("eachValueInSql=%s", eachValueInSql)
            formattedDictValueList.append(eachValueInSql)

        valueListSql = ", ".join(eachValue for eachValue in formattedDictValueList)
        logging.info("valueListSql=%s", valueListSql)

        insertSql = """INSERT INTO %s (%s) VALUES (%s)""" % (tablename, keyListSql, valueListSql)
        logging.info("insertSql=%s", insertSql)
        # INSERT INTO tbl_car_info_test (`url`, `mainBrand`, `subBrand`, `brandSerie`, `brandSerieId`, `model`, `modelId`, `modelStatus`, `cityDealerPrice`, `msrpPrice`) VALUES ("https://www.autohome.com.cn/spec/5872/#pvareaid=2042128", "宝马", "华晨宝马", "宝马3系", "66", "2010款 320i 豪华型", "5872", "停售", 325000, 375000)

        return self.executeSql(sqlStr=insertSql, actionDescription=("Insert value to table %s" % tablename))

    def delete(self, keyName, keyValue, tablename=curTableName):
        """
            delete item from car model id for existing table of autohome car info
        """
        logging.info("delete: keyName=%s, keyValue=%s, tablename=%s", keyName, keyValue, tablename)

        keyValueStr = str(keyValue)
        if keyValue is str:
            keyValueStr = "'%s'" % keyValue

        deleteSql = """DELETE FROM %s WHERE %s = %s""" % (tablename, keyName, keyValueStr)
        logging.info("deleteSql=%s", deleteSql)

        return self.executeSql(sqlStr=deleteSql, actionDescription=("Delete value from table %s by %s" % (tablename, keyName)))


################################################################################
# Test
################################################################################


def testMysqlDb():
    """test mysql"""

    testDropTable = True
    testCreateTable = True
    testInsertValue = True
    testDeleteValue = True

    # 1.test connect mysql
    mysqlObj = MysqlDb()
    logging.info("mysqlObj=%s", mysqlObj)

    # testTablename = "autohome_car_info"
    # testTablename = "tbl_car_info_test"
    testTablename = CurrentTableName
    logging.info("testTablename=%s", testTablename)

    if testDropTable:
        # 2. test drop table
        dropTableOk, errDict = mysqlObj.dropTable(testTablename)
        logging.info("dropTable %s return %s, errDict=%s", testTablename, dropTableOk, errDict)

    if testCreateTable:
        # 3. test create table
        createTableOk, errDict = mysqlObj.createTable(testTablename)
        logging.info("createTable %s return %s, errDict=%s", testTablename, createTableOk, errDict)

    if testInsertValue:
        # 4. test insert value dict
        valueDict = {
            "url": "https://www.autohome.com.cn/spec/5872/#pvareaid=2042128", #车型url
            "mainBrand": "宝马", #品牌
            "subBrand": "华晨宝马", #子品牌
            "brandSerie": "宝马3系", #车系
            "brandSerieId": "66", #车系ID
            "model": "2010款 320i 豪华型", #车型
            "modelId": "5872", #车型ID
            "modelStatus": "停售", #车型状态
            "cityDealerPrice": 325000, #经销商参考价
            "msrpPrice": 375000 # 厂商指导价
        }
        logging.info("valueDict=%s", valueDict)
        insertOk, errDict = mysqlObj.insert(valueDict=valueDict, tablename=testTablename)
        logging.info("insertOk=%s,errDict=%s", insertOk, errDict)

    if testDeleteValue:
        toDeleteModelId = "5872"
        deleteOk, errDict = mysqlObj.delete(modelId=toDeleteModelId, tablename=testTablename)
        logging.info("deleteOk=%s, errDict=%s", deleteOk, errDict)

if __name__ == '__main__':
    logging.info("[crifanLib-%s] %s", CURRENT_LIB_FILENAME, __version__)

    testMysqlDb()