/*
 * Javascript datetime realted functions
 * 
 * Author: Crifan Li
 * Updated: 20181122
 * 
 */

export const INVALID_DATE = new Date("1970/1/1");


//from "1500422400000" or 1500422400000 to Wed Jul 19 2017 08:00:00 GMT+0800 (CST)
export function timestampToDate(timestamp) {
  let convertedDate = null;

  let timestampInt = 0;
  if (typeof(timestamp) === "number") {
    timestampInt = timestamp;
  } else if (typeof(timestamp) === "string"){
    timestampInt = parseInt(timestamp, 10);
  }

  if (timestampInt > 0) {
    convertedDate = new Date(timestampInt);
  }

  // console.log(`timestamp=${timestamp} -> ${convertedDate}`);
  return convertedDate;
}

// from a date to "2017-06-30"
export function datetimeToStr(datetime, nullStr="", formatStr="yyyy-MM-dd"){
  // console.log(`datetime=${datetime},nullStr=${nullStr},formatStr=${formatStr}`);

  if ((datetime === null) || (datetime === INVALID_DATE))
    return nullStr;

  const formatedDate = datetime.Format(formatStr);

  // console.log(`datetime=${datetime},nullStr=${nullStr},formatStr=${formatStr} -> formatedDate=${formatedDate}`);
  return formatedDate;
}


//from "2017-02-22" to Date()
export function strToDatetime(datetimeStr){
  if ((datetimeStr === "") || (datetimeStr === null))
    return null;

  let convertedDate = new Date(datetimeStr);

  // console.log(`datetimeStr=${datetimeStr} -> convertedDate=${convertedDate}`);
  return convertedDate;
}

// 对Date的扩展，返回之前或之后的多少个小时的时间
// 例子：
// (new Date()).prevNextHours(5) /  (new Date()).prevNextHours(-7)
// ==>
// current date [Tue Jun 06 2017 08:00:00 GMT+0800 (CST)] + [7] hours -> [Tue Jun 06 2017 15:00:00 GMT+0800 (CST)]
Date.prototype.prevNextHours = function (hoursNumber) {
  // console.log(`Date prevNextHours: this=${this}, hoursNumber=${hoursNumber}`);

  // Note: here only got date pointer(reference) not date value, so later setHours will change this !!!
  // let tmpDate = this;
  let tmpDate = new Date(this);
  let changedDateTimestamp = tmpDate.setHours(tmpDate.getHours() + hoursNumber);
  // console.log(`changedDateTimestamp=${changedDateTimestamp}`);
  let changedDate = new Date(changedDateTimestamp);

  // console.log(`current date [${this}] + [${hoursNumber}] hours -> [${changedDate}]`);
  return changedDate;
};

// 对Date的扩展，返回时间戳(毫秒，13位)
// 例子：
// this=Tue Jun 06 2017 15:00:00 GMT+0800 (CST) -> 1496732400000
// Mon Nov 12 2018 11:03:47 GMT+0800 (中国标准时间) -> 1541991827756
Date.prototype.timestamp = function () {
  // console.log(`Date timesamp: this=${this}`);
  let timesamp = this.getTime();
  // console.log(`this=${this} -> timesamp=${timesamp}`);
  return timesamp
}
// console.debug("=== Test Date.timestamp ===")
// var curDate = new Date()
// console.log("curDate=%o", curDate)
// var curTimestamp = curDate.timestamp()
// console.log("curTimestamp=%o", curTimestamp)


// 对Date的扩展，将 Date 转化为指定格式的String
// 月(M)、日(d)、小时(h)、分(m)、秒(s)、季度(q) 可以用 1-2 个占位符，
// 年(y)可以用 1-4 个占位符，毫秒(S)只能用 1 个占位符(是 1-3 位的数字)
// 例子：
// (new Date()).Format("yyyy-MM-dd HH:mm:ss.S") ==> 2006-07-02 08:09:04.423
// (new Date()).Format("yyyy-M-d h:H:s.S")      ==> 2006-7-2 8:9:4.18
Date.prototype.Format = function (fmt) {
  const o = {
      "M+": this.getMonth() + 1, //月份
      "d+": this.getDate(), //日
      "H+": this.getHours(), //小时
      "m+": this.getMinutes(), //分
      "s+": this.getSeconds(), //秒
      "q+": Math.floor((this.getMonth() + 3) / 3), //季度
      "S": this.getMilliseconds() //毫秒
  };

  if (/(y+)/.test(fmt)){
      fmt = fmt.replace(RegExp.$1, (this.getFullYear() + "").substr(4 - RegExp.$1.length));
  }

  for (const k in o){
      if (new RegExp("(" + k + ")").test(fmt)){
      fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : (("00" + o[k]).substr(("" + o[k]).length)));
      }
  }
  return fmt;
}
// console.debug("=== Test Date.Format ===")
// var curDate = new Date()
// console.log("curDate=%o", curDate)
// var curDateStr1 = curDate.Format("yyyy-MM-dd") //2017-06-09
// var curDateStr2 = curDate.Format("yyyy-MM-dd HH:mm:ss") //2017-06-09 09:54:35
// var curDateStr3 = curDate.Format("yyyyMMdd_HHmmss") //20170609_095435
// console.log("curDateStr1=%o", curDateStr1)
// console.log("curDateStr2=%o", curDateStr2)
// console.log("curDateStr3=%o", curDateStr3)


/** * 对Date的扩展，将 Date 转化为指定格式的String * 月(M)、日(d)、12小时(h)、24小时(H)、分(m)、秒(s)、周(E)、季度(q)
   可以用 1-2 个占位符 * 年(y)可以用 1-4 个占位符，毫秒(S)只能用 1 个占位符(是 1-3 位的数字)
* eg:
* (new Date()).pattern("yyyy-MM-dd HH:mm:ss.S")==> 2006-07-02 08:09:04.423
* (new Date()).pattern("yyyy-MM-dd E HH:mm:ss") ==> 2009-03-10 二 20:09:04
* (new Date()).pattern("yyyy-MM-dd EE HH:mm:ss") ==> 2009-03-10 周二 08:09:04
* (new Date()).pattern("yyyy-MM-dd EEE HH:mm:ss") ==> 2009-03-10 星期二 08:09:04
* (new Date()).pattern("yyyy-M-d H:m:s.S") ==> 2006-7-2 8:9:4.18
*/
Date.prototype.pattern=function(fmt) {
  const o = {
    "M+" : this.getMonth()+1, //月份
    "d+" : this.getDate(), //日
    "h+" : this.getHours()%12 == 0 ? 12 : this.getHours()%12, //小时
    "H+" : this.getHours(), //小时
    "m+" : this.getMinutes(), //分
    "s+" : this.getSeconds(), //秒
    "q+" : Math.floor((this.getMonth()+3)/3), //季度
    "S" : this.getMilliseconds() //毫秒
  };

  if (/(y+)/.test(fmt)){
    fmt = fmt.replace(RegExp.$1, (this.getFullYear()+"").substr(4 - RegExp.$1.length));
  }

  if (/(E+)/.test(fmt)){
    fmt = fmt.replace(RegExp.$1, ((RegExp.$1.length>1) ? (RegExp.$1.length>2 ? "星期" : "周") : "") + "日一二三四五六".charAt(this.getDay()));
  }

  for (const k in o){
    if (new RegExp("("+ k +")").test(fmt)){
      fmt = fmt.replace(RegExp.$1, (RegExp.$1.length==1) ? (o[k]) : (("00"+ o[k]).substr((""+ o[k]).length)));
    }
  }

  return fmt;
}
// console.debug("=== Test Date.pattern ===")
// var curDate = new Date()
// console.log(curDate.pattern("yyyy-MM-dd EEE HH:mm:ss"))  //2017-06-09 星期五 10:16:12
// console.log(curDate.pattern("yyyy-MM-dd EE HH:mm:ss"))   //2017-06-09 周五 10:16:12
// console.log(curDate.pattern("yyyy-MM-dd E HH:mm:ss"))    //2017-06-09 五 10:16:12

