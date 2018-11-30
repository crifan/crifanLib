import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crifanDatetime import floatSecondsToDatetimeDict, datetimeDictToStr

if __name__ == "__main__":
  floatSeconds1 = 96400.3765293
  datetimeDict1 = floatSecondsToDatetimeDict(floatSeconds1)
  print("datetimeDict1=%s" % datetimeDict1) # {'days': 1, 'hours': 2, 'minutes': 46, 'seconds': 40, 'millseconds': 376, 'microseconds': 529}
  datetimeStr1 = datetimeDictToStr(datetimeDict1)
  print("datetimeStr1=%s" % datetimeStr1) # 1 02:46:40.376

  floatSeconds2 = 382.2865912
  datetimeDict2 = floatSecondsToDatetimeDict(floatSeconds2)
  print("datetimeDict2=%s" % datetimeDict2) # {'days': 0, 'hours': 0, 'minutes': 6, 'seconds': 22, 'millseconds': 286, 'microseconds': 591}
  datetimeStr2 = datetimeDictToStr(datetimeDict2)
  print("datetimeStr2=%s" % datetimeStr2) # 0 00:06:22.286
