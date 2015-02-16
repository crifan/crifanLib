/*
 * [File]
 * crifanLib..go
 * 
 * [Function]
 * 【记录】在用go语言成功模拟登陆百度后把相关函数整理至自己的go语言的库函数：crifanLib.go
 * http://www.crifan.com/after_use_go_language_emulate_login_baidu_arrage_common_func_to_crifanlib_go
 * 
 * [Version]
 * 2013-09-21
 *
 * [Contact]
 * http://www.crifan.com/about/me/
 */
package crifanLib

import (
    //"fmt"
    //"log"
    "os"
    //"runtime"
    //"path"
    //"strings"
    "time"
    //"io"
    "io/ioutil"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    //"sync"
    //"net/url"
    //"regexp"
    //"bufio"
    "bytes"
)

//import l4g "log4go.googlecode.com/hg"
//import l4g "code.google.com/p/log4go"
import "code.google.com/p/log4go"

/***************************************************************************************************
    Global Variables
***************************************************************************************************/
var gCurCookies []*http.Cookie;
var gCurCookieJar *cookiejar.Jar;
var gLogger log4go.Logger;

/***************************************************************************************************
    Private Functions
***************************************************************************************************/
//init for crifanLib
func init(){
    gCurCookies = nil
    gCurCookieJar,_ = cookiejar.New(nil)
    gLogger = nil
    
    //InitLogger() // caller should manually call this
}

// //de-init for all
// func deinitAll(){
    // gCurCookies = nil
    // if(nil == gLogger) {
        // gLogger.Close();
        // //os.Stdout.Sync() //try manually flush, but can not fix log4go's flush bug
        
        // gLogger = nil
    // }
// }

/***************************************************************************************************
    Public Functions
***************************************************************************************************/

//init for logger
func InitLogger(logFilename string) log4go.Logger {
    //var filenameOnly string = GetCurFilename()
    //var logFilename string =  filenameOnly + ".log";
    
    //gLogger = log4go.NewLogger()
    //gLogger = make(log4go.Logger)
    
    //for console
    //gLogger.AddFilter("stdout", log4go.INFO, log4go.NewConsoleLogWriter())
    gLogger = log4go.NewDefaultLogger(log4go.INFO)
    
    //for log file
    if _, err := os.Stat(logFilename); err == nil {
        //fmt.Printf("found old log file %s, now remove it\n", logFilename)
        os.Remove(logFilename)
    }
    //gLogger.AddFilter("logfile", log4go.FINEST, log4go.NewFileLogWriter(logFilename, true))
    //gLogger.AddFilter("logfile", log4go.FINEST, log4go.NewFileLogWriter(logFilename, false))
    gLogger.AddFilter("log", log4go.FINEST, log4go.NewFileLogWriter(logFilename, false))
    gLogger.Debug("Current time is : %s", time.Now().Format("15:04:05 MST 2006/01/02"))
    
    return gLogger
}

// //get current logger
// func GetCurLogger() log4go.Logger {
    // return gLogger
// }


//get url response html
func GetUrlRespHtml(strUrl string, postDict map[string]string) string{
    gLogger.Debug("in getUrlRespHtml, strUrl=%s", strUrl)
    gLogger.Debug("postDict=%s", postDict)
    
    var respHtml string = "";
    
    httpClient := &http.Client{
        //Transport:nil,
        //CheckRedirect: nil,
        Jar:gCurCookieJar,
    }

    var httpReq *http.Request
    //var newReqErr error
    if nil == postDict {
        gLogger.Debug("is GET")
        //httpReq, newReqErr = http.NewRequest("GET", strUrl, nil)
        httpReq, _ = http.NewRequest("GET", strUrl, nil)
        // ...
        //httpReq.Header.Add("If-None-Match", `W/"wyzzy"`)
    } else {
        //【记录】go语言中实现http的POST且传递对应的post data
        //http://www.crifan.com/go_language_http_do_post_pass_post_data
        gLogger.Debug("is POST")
        postValues := url.Values{}
        for postKey, PostValue := range postDict{
            postValues.Set(postKey, PostValue)
        }
        gLogger.Debug("postValues=%s", postValues)
        postDataStr := postValues.Encode()
        gLogger.Debug("postDataStr=%s", postDataStr)
        postDataBytes := []byte(postDataStr)
        gLogger.Debug("postDataBytes=%s", postDataBytes)
        postBytesReader := bytes.NewReader(postDataBytes)
        //httpReq, newReqErr = http.NewRequest("POST", strUrl, postBytesReader)
        httpReq, _ = http.NewRequest("POST", strUrl, postBytesReader)
        //httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
        httpReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    }
    
    httpResp, err := httpClient.Do(httpReq)
    // ...
    
    //httpResp, err := http.Get(strUrl)
    //gLogger.Info("http.Get done")
    if err != nil {
        gLogger.Warn("http get strUrl=%s response error=%s\n", strUrl, err.Error())
    }
    gLogger.Debug("httpResp.Header=%s", httpResp.Header)
    gLogger.Debug("httpResp.Status=%s", httpResp.Status)

    defer httpResp.Body.Close()
    // gLogger.Info("defer httpResp.Body.Close done")
    
    body, errReadAll := ioutil.ReadAll(httpResp.Body)
    //gLogger.Info("ioutil.ReadAll done")
    if errReadAll != nil {
        gLogger.Warn("get response for strUrl=%s got error=%s\n", strUrl, errReadAll.Error())
    }
    //gLogger.Debug("body=%s\n", body)

    //gCurCookies = httpResp.Cookies()
    //gCurCookieJar = httpClient.Jar;
    gCurCookies = gCurCookieJar.Cookies(httpReq.URL);
    //gLogger.Info("httpResp.Cookies done")
    
    //respHtml = "just for test log ok or not"
    respHtml = string(body)
    //gLogger.Info("httpResp body []byte to string done")

    return respHtml
}

//get current http cookies
func GetCurCookies() []*http.Cookie {
    return gCurCookies
}

//print http cookies
func DbgPrintCookies(httpCookies []*http.Cookie) {
    if nil != httpCookies {
        var cookieNum int = len(httpCookies);
        gLogger.Debug("cookieNum=%d", cookieNum)
        for i := 0; i < cookieNum; i++ {
            var curCk *http.Cookie = httpCookies[i];
            gLogger.Debug("------ Cookie [%d]------", i)
            gLogger.Debug("Name\t\t=%s", curCk.Name)
            gLogger.Debug("Value\t=%s", curCk.Value)
            gLogger.Debug("Path\t\t=%s", curCk.Path)
            gLogger.Debug("Domain\t=%s", curCk.Domain)
            gLogger.Debug("Expires\t=%s", curCk.Expires)
            gLogger.Debug("RawExpires\t=%s", curCk.RawExpires)
            gLogger.Debug("MaxAge\t=%d", curCk.MaxAge)
            gLogger.Debug("Secure\t=%t", curCk.Secure)
            gLogger.Debug("HttpOnly\t=%t", curCk.HttpOnly)
            gLogger.Debug("Unparsed\t=%s", curCk.Unparsed)
            gLogger.Debug("Raw\t\t=%s", curCk.Raw)
        }
    }
}
