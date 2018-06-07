import os
import sys
# print("--------- %s" % __file__)
currentCrifanLibPath = os.path.split(os.path.realpath(__file__))[0]
# print("currentCrifanLibPath=%s" % currentCrifanLibPath)
sys.path.append(currentCrifanLibPath)


# from . import crifanBeautifulsoup
# from . import crifanCookie
# from . import crifanDatetime
# from . import crifanEmail
# from . import crifanFile
# from . import crifanGeography
# from . import crifanHtml
# from . import crifanHttp
# from . import crifanList
# from . import crifanLogging
# from . import crifanMath
# from . import crifanMysql
# from . import crifanOpenpyxl
# from . import crifanString
# from . import crifanSystem
# from . import crifanTemplate
# from . import crifanUrl
