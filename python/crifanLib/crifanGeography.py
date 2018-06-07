#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanGeography.py
Function: crifanLib's geography related functions.
Version: v1.0 20180605
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v1.0"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

from math import radians, cos, sin, asin, sqrt

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanGeography"

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
# Geography Function
################################################################################

def calcDistance(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)

    Reference:
        http://stackoverflow.com/questions/4913349/haversine-formula-in-python-bearing-and-distance-between-two-gps-points
        def haversine(lon1, lat1, lon2, lat2):
    """
    # convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    EARTH_RADIUS = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * EARTH_RADIUS



def getZipcodeFromLocation(locationStr):
    """
        get zip code from location string, especially for USA
        eg:
        intput: Tampa, FL
        output: 33601

        input: West Palm Beach, FL
        output: 33401
    """
    zipCode = "";
    gotZipCode = False;

    if (not gotZipCode):
        # Method 1:
        # http://autoexplosion.com/templates/zip_search.php
        cityStateList = locationStr.split(",")
        # logging.debug("cityStateList=%s", cityStateList)
        city = cityStateList[0].strip()
        state = cityStateList[1].strip()
        # logging.debug("city=%s, state=%s", city, state)
        # http://autoexplosion.com/templates/zip_search.php?formname=search&city=Tampa&state=FL
        zipBaseSearchUrl = "http://autoexplosion.com/templates/zip_search.php"
        paraDict = {
            'formname': "search",
            'city': city,
            'state': state,
        };
        # http://autoexplosion.com/templates/zip_search.php?city=San Antonio&state=TX&formname=search
        encodedPara = urllib.urlencode(paraDict)
        # logging.debug("encodedPara=%s", encodedPara)

        # zipSearchUrl = genFullUrl(zipBaseSearchUrl, paraDict)
        zipSearchUrl = zipBaseSearchUrl + "?" + encodedPara
        # logging.debug("zipSearchUrl=%s", zipSearchUrl)

        headerDict = {
            'Referer': "http://autoexplosion.com/templates/zip_search.php?formname=search",
        }
        zipSearchRespHtml = getUrlRespHtml(zipSearchUrl, headerDict=headerDict)
        # logging.debug("zipSearchRespHtml=%s", zipSearchRespHtml)

        # found the first zip search result
        # <tr>				<td colspan="2" class="cssTableCellLeft">&nbsp;San Antonio</td>
        # <td align="center">TX</td>
        # <td colspan="2" align="center" class="cssTableCellRight"><a href="javascript:paste_zip('78201');">78201</a></td>
        # </tr>
        soup = BeautifulSoup(zipSearchRespHtml)
        foundZipcode = soup.find(name="td", attrs={"class": "cssTableCellRight"})
        logging.debug("foundZipcode=%s", foundZipcode)
        if (foundZipcode):
            zipCode = foundZipcode.a.string  # 78201
            # logging.debug("zipCode=%s", zipCode)

            gotZipCode = True;
        else:
            logging.debug("Failed for method 1, from %s", locationStr);
            gotZipCode = False;

    # Method 2:
    # https://tools.usps.com/go/ZipLookupAction_input
    if (not gotZipCode):
        # https://tools.usps.com/go/ZipLookupAction.action
        zipLookupBaseUrl = "https://tools.usps.com/go/ZipLookupAction.action";
        # post data:
        # mode=0&tCompany=&tZip=&tAddress=&tApt=&tCity=WEST+PALM+BEACH&sState=FL&tUrbanCode=&zip=
        paraDict = {
            'mode': "0",
            'tCompany': "",
            'tZip': "",
            'tAddress': "",
            'tApt': "",
            'tCity': city,
            'sState': state,
            'tUrbanCode': "",
            "zip": "",

        };
        encodedPara = urllib.urlencode(paraDict);
        logging.debug("encodedPara=%s", encodedPara);
        zipLookupUrl = zipLookupBaseUrl + "?" + encodedPara;
        logging.debug("zipLookupUrl=%s", zipLookupUrl);

        headerDict = {
            'Referer': "https://tools.usps.com/go/ZipLookupAction_input",
        };
        zipLookupRespHtml = getUrlRespHtml(zipLookupUrl, headerDict=headerDict);
        # logging.debug("zipLookupRespHtml=%s", zipLookupRespHtml);
        # <span class="zip" style="">33401</span>
        soup = BeautifulSoup(zipLookupRespHtml);
        foundZip = soup.find(name="span", attrs={"class": "zip", "style": ""});
        logging.debug("foundZip=%s", foundZip);
        if (foundZip):
            zipCode = foundZip.string;  # 33401
            logging.debug("zipCode=%s", zipCode);

            gotZipCode = True;
        else:
            logging.debug("Failed for method 2, from %s", locationStr);
            gotZipCode = False;

    return zipCode;

################################################################################
# Test
################################################################################



if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))