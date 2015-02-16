/*
 * [File]
 * crifanLib.c
 * 
 * [Function]
 * This library file contains many common functions, implemented in ANSI C, created by crifan.
 * 
 * [Note]
 * 
 * [Version]
 * v1.0
 * 
 * [update]
 * 2013-07-04
 * 
 * [Author]
 * Crifan Li
 * 
 * [Contact]
 * http://www.crifan.com/contact_me/
 * http://www.crifan.com/crifan_released_all/crifanlib/
 * 
 * [History]
 * [v1.0]
 * 1. initial version, not verify code yet
 */
 
/**************************************************************************************************
    Macro Definitions
***************************************************************************************************/
/* use for only test several times in a loop */
#define MAX_TEST_COUNT              15

/**************************************************************************************************
    Include Files
***************************************************************************************************/
#include <time.h>
#include <sys/stat.h>

/**************************************************************************************************
    Global Variables
***************************************************************************************************/

/**************************************************************************************************
    Functions
***************************************************************************************************/

/**************************************************************************************************/
/* Time */
/**************************************************************************************************/
// How to calculate the elapsed time
//http://www.crifan.com/how_to_calculate_the_elapsed_time/
public void showCalculateElapsedTime()
{
    struct timeval  tv_begin_mdct, tv_end_mdct;
    int test_count=0; // test times
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
        mdct_time = tv_end_mdct.tv_usec – tv_begin_mdct.tv_usec;
        printf(" The mdct time of the %d frame is ttt%ld msn", test_count, mdct_time/1000);
    }
}


/**************************************************************************************************/
/* File */
/**************************************************************************************************/

//http://www.crifan.com/order_how_to_calculate_the_file_size__length_caculate_the_file_length__size/
//calculate file size/length
//return negative if error

//method 1: use fgetc
//good: universial
//bad: maybe overflow if files too large
public long calulateFilesize_fgetc(string inputFilename)
{
    long filesize = 0;
    
    inputFp = fopen(inputFilename, "rb");

    if (!inputFp) {
        //printf("Error opening input file %s", inputFilename);
        return -1;
    }

    /* caculate the file length(bytes) */
    singleChar = fgetc(inputFp);
    while(EOF != singleChar)
    {
        ++filesize;
        singleChar = fgetc(inputFp);
    }
    
    return filesize;
}

//method 2: fseek + ftell
//good: fast
//bad: 
public long calulateFilesize_ftell(string inputFilename)
{
    long filesize = 0;
    
    inputFp = fopen(inputFilename, "rb");

    if (!inputFp) {
        //printf("Error opening input file %s", inputFilename);
        return -1;
    }

    /*
        标识符     数值     代表的起始点
        SEEK_SET   0        文件开始
        SEEK_END   2        文件末尾
        SEEK_CUR   1        文件当前位置
    */

    fseek(inputFp, 0, SEEK_END);

    filesize = ftell(inputFp);
    
    return filesize;
}

//method 3: fstat
//good: fast
//bad: system dependent
public long calulateFilesize_fstat(string inputFilename)
{
    long filesize = 0;
    //http://linux.die.net/man/2/fstat
    struct stat fileStat;
    
    //http://www.go4expert.com/articles/understanding-linux-fstat-example-t27449/
    inputFileDescriptor = open(inputFilename, O_RDONLY);
    if (inputFileDescriptor < 0) {
        //open file error
        return inputFileDescriptor;
    }

    fstatRet = fstat(inputFileDescriptor, &fileStat);
    if (fstatRet < 0)
    {
        close(inputFileDescriptor);
        
        return fstatRet;
    }

    filesize = fileStat.st_size;
    
    close(inputFileDescriptor);
    
    return filesize;
}
