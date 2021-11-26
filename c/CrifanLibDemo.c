/*
    File: CrifanLibDemo.c
    Function: crifan's common C lib function demo
    Author: Crifan Li
    Latest: https://github.com/crifan/crifanLib/blob/master/c/CrifanLibDemo.c
    Updated: 20211126_1902
*/

#include <stdio.h>
#include <sys/time.h>

/**************************************************************************************************/
/* Time */
/**************************************************************************************************/
void showCalculateElapsedTime(void);

/* use for only test several times in a loop */
#define MAX_TEST_COUNT              15

// How to calculate the elapsed time
//http://www.crifan.com/how_to_calculate_the_elapsed_time/
void showCalculateElapsedTime(void){
    struct timeval  tv_begin_mdct, tv_end_mdct;
    int test_count = 0; // test times
    // every part of encoder time of one frame in milliseconds
    long mdct_time = 0;

    //calculate mdct time of one of the firt ten frames
    if(test_count <= MAX_TEST_COUNT)
    {
        gettimeofday(&tv_begin_mdct, 0);
    }

    // ......
    // do what you wan to do 
    // ......
    //Func();

    //calculate mdct time of one of the firt ten frames
    if( test_count <= MAX_TEST_COUNT )
    {
        gettimeofday(&tv_end_mdct, 0);
        mdct_time = tv_end_mdct.tv_usec - tv_begin_mdct.tv_usec;
        printf("The mdct time of the %d frame is ttt%ld msn", test_count, mdct_time/1000);
    }
}

