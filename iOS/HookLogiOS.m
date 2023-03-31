/*
    File: HookLogiOS.m
    Function: crifan's common iOS hook log functions
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/iOS/HookLogiOS.m
    Updated: 20230331_1455
*/

#import "HookLogiOS.h"

/*==============================================================================
 Global Config
==============================================================================*/

// output one log every N time
//long LOG_ONCE_PER_NUM = 10;
//long LOG_ONCE_PER_NUM = 20;
long LOG_ONCE_PER_NUM = 100;

/*==============================================================================
 Global Variable
==============================================================================*/

long gCurLogNum = 0;

//only for debug
long gNoUse = 0;

@implementation HookLogiOS

@end
