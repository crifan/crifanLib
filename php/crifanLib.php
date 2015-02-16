<?php
/*
[Filename]
crifanLib.php

[Function]
crifan's php lib, implement common functions

[Author]
Crifan Li

[Contact]
http://www.crifan.com/contact_me/

[Note]
1.online see code:
http://code.google.com/p/crifanlib/source/browse/trunk/php/crifanLib.php

[TODO]

[History]
[v1.0]
1.initial version, need clean up later

*/

/**
 * add newline for print
 */
function printAutoNewline($contentToPrint) {
    print_r($contentToPrint."<br />");
}


//http://php.net/manual/en/book.curl.php
function http_response($url, $status = null, $wait = 3)
{
    $time = microtime(true);
    $expire = $time + $wait;

    // we fork the process so we don't have to wait for a timeout
    $pid = pcntl_fork();
    if ($pid == -1) {
        die('could not fork');
    } else if ($pid) {
        // we are the parent
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);

        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        //curl_setopt($ch, CURLOPT_NOBODY, TRUE); // remove body
        //curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        $head = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
       
        if(!$head)
        {
            return FALSE;
        }
       
        if($status === null)
        {
            if($httpCode < 400)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        elseif($status == $httpCode)
        {
            return TRUE;
        }
       
        return FALSE;
        pcntl_wait($status); //Protect against Zombie children
    } else {
        // we are the child
        while(microtime(true) < $expire)
        {
        sleep(0.5);
        }
        return FALSE;
    }
}

//http://cn2.php.net/manual/zh/function.fsockopen.php
function getUrlRespHtml_fsockopen($url) {
    printAutoNewline("input url=".$url);

    $respHtml = "";
    
    //resource fsockopen ( string $hostname [, int $port = -1 [, int &$errno [, string &$errstr [, float $timeout = ini_get("default_socket_timeout") ]]]] )
    // $testHostname = "www.yell.com";
    // $fp = fsockopen($testHostname, 80, $errno, $errstr, 30);
    // if (!$fp) {
        // echo "$errstr ($errno)<br />\n";
    // } else {
        // $getRequest = "GET / HTTP/1.1\r\n";
        // $getRequest .= "Host: ".$testHostname."\r\n";
        // $getRequest .= "Connection: Close\r\n\r\n";
        // fwrite($fp, $getRequest);
        // while (!feof($fp)) {
            // $curRespHtml = fgets($fp, 128);
            // printAutoNewline($curRespHtml);
            // $respHtml += $curRespHtml;
        // }
        // fclose($fp);
    // }
    //printAutoNewline($respHtml);
    
    http_response($url,'200',3); // returns true if the response takes less than 3 seconds and the response code is 200 
    
    return $respHtml;
}

/*
 *【已解决】PHP中把字符串文本等数据保存到文件中
 * http://www.crifan.com/php_how_to_save_string_text_data_into_file/
 */
function saveToFile($dataToOutput, $fullFilename)
{
    // $outputFp = fopen($outputFilename, 'w') or die("can't create file".$outputFilename);
    // fwrite($outputFp, $response);
    // fclose($outputFp);

    $saveResult = file_put_contents($fullFilename, $dataToOutput);
    printAutoNewline("Write data to ".$fullFilename." ok.");
    
    return $saveResult;
}

/*
 * 【已解决】PHP中如何实现路径拼接(两个路径合并)以及合并文件夹路径和文件名
 * http://www.crifan.com/php_path_concatenation_combine_directory_and_filename
 * eg:
 * from:
 * D:\tmp\WordPress\DevRoot\httpd-2.2.19-win64\httpd-2.2-x64\htdocs\php_test\35934503_data
 * cookie_jar.txt
 * to:
 * D:\tmp\WordPress\DevRoot\httpd-2.2.19-win64\httpd-2.2-x64\htdocs\php_test\35934503_data\cookie_jar.txt
 */
function concatenatePath($headPath, $tailPath)
{
    $realHeadPath = realpath($headPath);
    #printAutoNewline("realHeadPath=".$realHeadPath);
    //$realTailPath = realpath($tailPath);
    //printAutoNewline("realTailPath=".$realTailPath);
    //$concatnatedPath = $realHeadPath.DIRECTORY_SEPARATOR.$realTailPath;
    #printAutoNewline("tailPath=".$tailPath);
    
    $concatnatedPath = $realHeadPath.DIRECTORY_SEPARATOR.$tailPath;
    #printAutoNewline("concatnatedPath=".$concatnatedPath);
    return $concatnatedPath;
}

//http://cn2.php.net/curl_setopt
function getUrlRespHtml($url)
{
    printAutoNewline("now to get response from url=".$url);
    
    //get the file (e.g. image) and output it to the browser
    $ch = curl_init(); //open curl handle
    curl_setopt($ch, CURLOPT_URL, $url); //set an url
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //do not output directly, use variable
    curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1); //do a binary transfer
    curl_setopt($ch, CURLOPT_FAILONERROR, 1); //stop if an error occurred
    
    curl_setopt($ch, CURLOPT_AUTOREFERER, 1); //当根据Location:重定向时，自动设置header中的Referer:信息。 
    
    #printAutoNewline("now add CURLOPT_COOKIEJAR support");
    $cookieJarFilename = "cookie_jar.txt";
    //$cookieJarFullname = dirname(__FILE__).$cookieJarFilename;
    $cookieJarFullname = concatenatePath(dirname(__FILE__), $cookieJarFilename);
    printAutoNewline("cookieJarFullname=".$cookieJarFullname);
    curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieJarFullname);
    curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieJarFullname);
    
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)");
    
    $requestHeader[0] = "Accept: text/html, application/xhtml+xml, */*,";
    //$requestHeader[] = "Cache-Control: max-age=0";
    $requestHeader[] = "Connection: keep-alive";
    //$requestHeader[] = "Keep-Alive: 300";
    //$requestHeader[] = "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7";
    //$requestHeader[] = "Accept-Language: en-us,en;q=0.5";
    //$requestHeader[] = "Pragma: "; // browsers keep this blank.
    curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeader); 

    $response = curl_exec($ch); //store the content in variable
    
    if(!curl_errno($ch))
    {
        //send out headers and output
        header("Content-type: ".curl_getinfo($ch, CURLINFO_CONTENT_TYPE)."");
        header("Content-Length: ".curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD)."");

        //printAutoNewline($response);
    }
    else{
        printAutoNewline('Curl error: ' . curl_error($ch));
    }
    curl_close($ch); //close curl handle

    return $response;
}

printAutoNewline("DIRECTORY_SEPARATOR=".DIRECTORY_SEPARATOR);

$yellEntryUrl = "http://www.yell.com/";
$yesllRespHtml = getUrlRespHtml($yellEntryUrl);
//printAutoNewline("yesllRespHtml=".$yesllRespHtml);
$outputFilename = "respHtml.html";
saveToFile($yesllRespHtml, $outputFilename);


$keywords = "plumbers";
$yellSearchUrl = "http://www.yell.com/ucs/UcsSearchAction.do?keywords=".$keywords."&location=&scrambleSeed=30792452&searchType=&M=&bandedclarifyResults=&ssm=1";
$searchRespHtml = getUrlRespHtml($yellSearchUrl);
saveToFile($yesllRespHtml, "searchResult.html");

// $outestDivPattern = '#<div class="\S+" name="\S+">(.+)</div>#is';

// preg_match($outestDivPattern, $testStr, $matches);
// print_r($matches); #注意，通过网页方式查看打印出来的字符，是看不到div的，需要查看网页源代码，就可以看出来对应的div了

 ?>