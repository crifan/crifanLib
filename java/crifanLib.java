/*
	File: crifanLib.java
	Function: crifan's common java related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/crifanLib.java
	Updated: 20240731
*/

//package crifan.com;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

//import java.net.CookieManager;
//import java.net.CookiePolicy;
//import java.net.HttpCookie;
import java.net.URISyntaxException;
import java.net.URI;
import java.net.URLDecoder;

import java.text.SimpleDateFormat;

//import java.util.Calendar;
import java.util.Date;
//import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Iterator;

import java.nio.charset.StandardCharsets;

import org.json.JSONObject;
import org.json.JSONException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;

import org.apache.http.NameValuePair;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
//import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.protocol.ClientContext;

import org.apache.http.cookie.Cookie;

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
//import org.apache.http.impl.cookie.BasicClientCookie;

import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
//import org.apache.http.params.HttpConnectionParams;
//import org.apache.http.params.HttpProtocolParams;
//import org.apache.http.params.HttpParams;
//import org.apache.http.params.DefaultedHttpParams;
import org.apache.http.params.CoreProtocolPNames;

import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;


import org.apache.http.util.EntityUtils;

import info.monitorenter.cpdetector.io.ASCIIDetector;
import info.monitorenter.cpdetector.io.CodepageDetectorProxy;
import info.monitorenter.cpdetector.io.JChardetFacade;
import info.monitorenter.cpdetector.io.ParsingDetector;
import info.monitorenter.cpdetector.io.UnicodeDetector;

//for android:
//import crifan.com.downloadsongtastemusic.R;
//import android.os.Environment;
//import android.widget.EditText;
//import android.app.Activity;

public class crifanLib {
	private CookieStore gCurCookieStore = null;
	//private HashMap<Object, Object> calcTimeKeyDict;
	private HashMap<String, Long> calcTimeKeyDict;
	//private Map<String, Long> calcTimeKeyDict;

    //IE7
	private static final String constUserAgent_IE7_x64 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)";
    //IE8
	private static final String constUserAgent_IE8_x64 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E";
    //IE9
	private static final String constUserAgent_IE9_x64 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"; // x64
	private static final String constUserAgent_IE9_x86 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"; // x86
    //Chrome
	private static final String constUserAgent_Chrome = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4";
    //Mozilla Firefox
	private static final String constUserAgent_Firefox = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:1.9.2.6) Gecko/20100625 Firefox/3.6.6";
	
	private static String gUserAgent = "";
	
	
	public crifanLib()
	{
		gUserAgent = constUserAgent_IE8_x64;
		gCurCookieStore = new BasicCookieStore();
		
		calcTimeKeyDict = new HashMap<String, Long>();
	}

/*==============================================================================
 String
==============================================================================*/

	//remove first and last quote char "
	//eg: "xxx" -> xxx
	public static String trimQuote(String inputStr){
		String trimmedStr = null;
		if(null != inputStr){
			trimmedStr = inputStr;
			if(trimmedStr.startsWith("\"")){
				//remove first "
				trimmedStr = trimmedStr.substring(1);
			}
			
			if(trimmedStr.endsWith("\"")){
				//remove last "
				trimmedStr = trimmedStr.substring(0, trimmedStr.length() - 1);
			}
		}
		return trimmedStr;
	}

	/** Extract single string from input whole string
	 *	Note:
	 *    1. input pattern should include one group, like 'xxx(xxx)xxx'
	 *    2. output is in extractedStr
	*/
	public Boolean extractSingleStr(String pattern, String extractFrom, int flags, StringBuilder extractedStr)
	{
		Pattern strP = Pattern.compile(pattern, flags);
		Matcher foundStr = strP.matcher(extractFrom);
		Boolean found = foundStr.find();
		if(found)
		{
			extractedStr.append(foundStr.group(1));
		}
		return found;
	}

	/**
	 * None pattern version of extractSingleStr
	*/
	public Boolean extractSingleStr(String pattern, String extractFrom, StringBuilder extractedStr)
	{
		return extractSingleStr(pattern, extractFrom, 0, extractedStr);
	}

/*==============================================================================
 Date & Time
==============================================================================*/

	/** start calculate time */
	public long calcTimeStart(String uniqueKey)
	{
		long startMilliSec = 0;
		startMilliSec = System.currentTimeMillis(); //1373525642597
		calcTimeKeyDict.put(uniqueKey, startMilliSec); //{load_dd_file=1373525642597}
		return startMilliSec;
	}
	
	/** end calculate time */
	public long calcTimeEnd(String uniqueKey)
	{
		long endMilliSec = System.currentTimeMillis(); //1373525686178
		
		long elapsedMilliSec = 0;
		if(calcTimeKeyDict.containsKey(uniqueKey))
		{
			long startMilliSec = calcTimeKeyDict.get(uniqueKey); //1373525642597
			elapsedMilliSec = endMilliSec - startMilliSec; //43581
		}
		
		return elapsedMilliSec;
	}
	
	/* format date value into string */
	public static String dateToString(Date date, String format)
	{
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat(format);
		//Thu Nov 21 18:11:56 CST 2013  -->> 2013-11-21_181156
		String datetimeStr =simpleDateFormat.format(date);
		return datetimeStr;
	}
	
	/* get current date time string */
	public static String getCurrentDatetimeStr()
	{
		String curDatetimeStr = "";
		Date curDate = new Date(); //Thu Nov 21 18:11:56 CST 2013
		//12 hour format
		//curDatetimeStr = dateToString(curDate, "yyyy-MM-dd_hhmmss"); //2013-11-21_061156
		//24 hour format
		curDatetimeStr = dateToString(curDate, "yyyy-MM-dd_HHmmss"); //2013-11-21_181156
		return curDatetimeStr;
	}

/*==============================================================================
 List
==============================================================================*/

	// for  [a, b, c] and [c, b, a, b], here isListEqual -> true = means equal
	// if you think is not equal -> then should modify isListEqual's code logic
	public static boolean isListEqual(List list1, List list2){
//        boolean isEqual = CollectionUtils.isEqualCollection(list1, list2));
			boolean isEqual = list1.containsAll(list2) && list2.containsAll(list1);
			return isEqual;
	}

/*==============================================================================
 Map & Dict & Json
==============================================================================*/

	public static JSONObject mergeJson(JSONObject json1, JSONObject json2) throws JSONException {
		JSONObject mergedJson = new JSONObject();
		JSONObject[] jsonObjList = new JSONObject[] { json1, json2 };
		// Utils.logD(String.format("jsonObjList=%s", jsonObjList));
		for (JSONObject jsonObj : jsonObjList) {
				Iterator keyIterator = jsonObj.keys();
				// Utils.logD(String.format("keyIterator=%s", keyIterator));
				while (keyIterator.hasNext()) {
					String curKey = (String)keyIterator.next();
					Object curValue = jsonObj.opt(curKey);
					// Utils.logD(String.format("curKey=%s, curValue=%s", curKey, curValue));
					mergedJson.put(curKey, curValue);
				}
		}
		return mergedJson;
	}

	public static JSONObject mapToJson(Map<String, String> mapDict){
			JSONObject jsonObj = new JSONObject(mapDict);
			return jsonObj;
	}

	public static String mapToJsonStr(Map<String, String> mapDict){
			String jsonObjStr = mapToJson(mapDict).toString();
			return jsonObjStr;
	}

	public static JSONObject strToJson(String jsonStr){
		JSONObject jsonObj = null;
		// Utils.logD(String.format("strToJson: jsonStr=%s", jsonStr));
		try {
				jsonObj = new JSONObject(jsonStr);
				// Utils.logD(String.format("strToJson: jsonObj=%s", jsonObj));
		}catch (JSONException err){
				// Utils.logD(String.format("strToJson failed: %s", err.toString()));
		}
		return jsonObj;
	}

	public static List<Object> jsonArrToList(JSONArray array) throws JSONException {
			List<Object> list = new ArrayList<>();
			for(int i = 0; i < array.length(); i++) {
					Object value = array.get(i);
					if (value instanceof JSONArray) {
							value = jsonArrToList((JSONArray) value);
					}
					else if (value instanceof JSONObject) {
							value = jsonToMap((JSONObject) value);
					}
					list.add(value);
			}   return list;
	}

	public static Map<String, Object> jsonToMap(JSONObject jsonObj) throws JSONException {
			Map<String, Object> jsonMap = new HashMap<String, Object>();
			Iterator<String> keys = jsonObj.keys();
			while(keys.hasNext()) {
					String key = keys.next();
					Object value = jsonObj.get(key);
					if (value instanceof JSONArray) {
							value = jsonArrToList((JSONArray) value);
					} else if (value instanceof JSONObject) {
							value = jsonToMap((JSONObject) value);
					}
					jsonMap.put(key, value);
			}
			return jsonMap;
	}

/*==============================================================================
 Url
==============================================================================*/

	/**
	 * Parse out query string map/dict from url
	 * @param url url
	 * @return query string map/dict
	 */
	public static Map<String, String> parseUrlQsPara(String url) throws URISyntaxException, UnsupportedEncodingException {
			// Utils.logD(String.format("parseUrlQsPara: url=%s", url));
			Map<String, String> urlQsParaDict = new HashMap<String, String>();
			URI uri = new URI(url);
			// Utils.logD(String.format("uri=%s", uri));
			String scheme = uri.getScheme();
			String host = uri.getHost();
			// Utils.logD(String.format("scheme=%s, host=%s", scheme, host));
			String rawQuery = uri.getRawQuery();
			// Utils.logD(String.format("rawQuery=%s", rawQuery));
//        String decodedQuery = null;
//        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
//            decodedQuery = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8);
//        }
			String decodedQuery = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8.toString());
			// Utils.logD(String.format("decodedQuery=%s", decodedQuery));
//        String[] paraList = rawQuery.split("&");
			String[] paraList = decodedQuery.split("&");
			// Utils.logD(String.format("paraList=%s", paraList.toString()));
			for (String eachPara : paraList) {
					// Utils.logD(String.format("eachPara=%s", eachPara));
					String[] paraKeyValueList = eachPara.split("=");
					String paraKey = paraKeyValueList[0];
					String paraValue = paraKeyValueList[1];
					urlQsParaDict.put(paraKey, paraValue);
			}
			// Utils.logD(String.format("urlQsParaDict=%s", urlQsParaDict));
			return urlQsParaDict;
	}

/*==============================================================================
 File & Folder
==============================================================================*/

	public static String combinePath(String path1, String path2)
	{
	    File file1 = new File(path1);
	    File file2 = new File(file1, path2);
	    return file2.getPath();
	}
	
	public String getFileEncode(String path) throws IllegalArgumentException, FileNotFoundException, IOException {
		CodepageDetectorProxy detector = CodepageDetectorProxy.getInstance();
		detector.add(new ParsingDetector(false));
		detector.add(JChardetFacade.getInstance());
		detector.add(ASCIIDetector.getInstance());
		detector.add(UnicodeDetector.getInstance());
		java.nio.charset.Charset charset = null;
		File f = new File(path);

		charset = detector.detectCodepage(f.toURI().toURL());
		
		if (charset != null)
			return charset.name();
		else
			return null;
	}

	public static String readFileContentStr(String fullFilename)
	{
		String readOutStr = null;
		
        try {
//          //BufferedReader bufReader = new BufferedReader(new FileReader(fullFilename));
//          InputStreamReader isr = new InputStreamReader(new FileInputStream(fullFilename), "UTF-8");
//          BufferedReader bufReader = new BufferedReader(isr);
//          
//          String lineSeparator = System.getProperty("line.separator");
//          
//          String line = "";
//          while( ( line = bufReader.readLine() ) != null)
//          {
//          	readOutStr += line + lineSeparator;
//          }
//          bufReader.close();
      	
            DataInputStream dis = new DataInputStream(new FileInputStream(fullFilename));
            try {
                long len = new File(fullFilename).length();
                if (len > Integer.MAX_VALUE) throw new IOException("File "+fullFilename+" too large, was "+len+" bytes.");
                byte[] bytes = new byte[(int) len];
                dis.readFully(bytes);
                readOutStr = new String(bytes, "UTF-8");
            } finally {
                dis.close();
            }

			//Log.d("readFileContentStr", "Successfully to read out string from file "+ fullFilename);
        } catch (IOException e) {
        	readOutStr = null;

	    	//e.printStackTrace();
	    	//Log.d("readFileContentStr", "Fail to read out string from file "+ fullFilename);
		}
        
        return readOutStr;
	}

	/* output string into file */
	public static boolean outputStringToFile(String strToOutput, String fullFilename)
	{
		boolean ouputOk = true;
				
		try {
			/* Method1 */
			File newTextFile = new File(fullFilename);
			FileWriter fw;
			fw = new FileWriter(newTextFile);
			fw.write(strToOutput);
			fw.close();

			/* Method2 */
			/*
				//FileOutputStream ouputStream = openFileOutput(fullFilename, MODE_PRIVATE);
				FileOutputStream ouputStream = new FileOutputStream(fullFilename);
				byte [] preprocessedBytes = strToOutput.getBytes(); 
				ouputStream.write(preprocessedBytes); 
				ouputStream.close();
			*/

			//Log.d("outputStringToFile", "Successfully to save string to file: "+fullFilename);
		} catch (IOException e) {
			ouputOk = false;
			
			//e.printStackTrace();
			//Log.d("outputStringToFile", "Fail to save string to file: "+fullFilename);
		}

		return ouputOk;
	}

/*==============================================================================
 Http Network
==============================================================================*/

	public void dbgPrintCookies(List<Cookie> cookieList, String url)
	{
		if((null != url) && (!url.isEmpty()))
		{
			System.out.println("Cookies for " + url);
		}
		
		for(Cookie ck : cookieList)
		{
			System.out.println(ck);
		}
	}
	
	public void dbgPrintCookies(CookieStore cookieStore)
	{
		dbgPrintCookies(cookieStore, null);
	}
	
	public void dbgPrintCookies(CookieStore cookieStore, String url)
	{
		List<Cookie> cookieList = cookieStore.getCookies();
		dbgPrintCookies(cookieList, url);
	}
	
	public void dbgPrintCookies(List<Cookie> cookieList)
	{
		dbgPrintCookies(cookieList, null);
	}
	
	public CookieStore getCurCookieStore()
	{
		return gCurCookieStore;
	}

	public List<Cookie> getCurCookieList()
	{
		if(null != gCurCookieStore)
		{
			return gCurCookieStore.getCookies();
		}
		else
		{
			return null;
		}
	}

	public void setCurCookieStore(CookieStore newCookieStore)
	{
		gCurCookieStore = newCookieStore;
	}

	public void setCurCookieList(List<Cookie> newCookieList)
	{
		gCurCookieStore.clear();
		for(Cookie eachNewCk : newCookieList)
		{
			gCurCookieStore.addCookie(eachNewCk);
		}
	}
	
	
	/** Get response from url  */
	public HttpResponse getUrlResponse(
			String url,
			List<NameValuePair> headerDict,
			List<NameValuePair> postDict,
			int timeout
			)
	{
		// init
		HttpResponse response = null;
		HttpUriRequest request = null;
		DefaultHttpClient httpClient = new DefaultHttpClient();
		
		//HttpParams headerParams = new HttpParams();
		//HttpParams headerParams = new DefaultedHttpParams(headerParams, headerParams);
		//HttpParams headerParams = new BasicHttpParams();
		BasicHttpParams headerParams = new BasicHttpParams();
		//HttpConnectionParams.
		//default enable auto redirect
		headerParams.setParameter(CoreProtocolPNames.USER_AGENT, gUserAgent);
		headerParams.setParameter(ClientPNames.HANDLE_REDIRECTS, Boolean.TRUE);
		
		headerParams.setParameter(CoreConnectionPNames.SO_KEEPALIVE, Boolean.TRUE);
		
		if(postDict != null)
		{
			HttpPost postReq = new HttpPost(url);
			
			try{
				HttpEntity postBodyEnt = new UrlEncodedFormEntity(postDict);
				postReq.setEntity(postBodyEnt);
			}
			catch(Exception e){
				e.printStackTrace();
			}

			request = postReq;
		}
		else
		{
				HttpGet getReq = new HttpGet(url);
				
				request = getReq;
		}

		if(headerParams != null)
		{
			//HttpProtocolParams.setUserAgent(headerParams, gUserAgent);
			//headerParams.setHeader(HttpMethodParams.USER_AGENT, gUserAgent);
			request.setParams(headerParams);
		}
		
		//request.setHeader("User-Agent", gUserAgent);

		try{			
			HttpContext localContext = new BasicHttpContext();
			localContext.setAttribute(ClientContext.COOKIE_STORE, gCurCookieStore);
			response = httpClient.execute(request, localContext);
			
			//response HeaderGroup value:
			//[Via: 1.1 SC-SZ-06, Connection: Keep-Alive, Proxy-Connection: Keep-Alive, Content-Length: 11006, Expires: Tue, 17 Sep 2013 01:43:44 GMT, Date: Tue, 17 Sep 2013 01:43:44 GMT, Content-Type: text/html;charset=utf-8, Server: BWS/1.0, Cache-Control: private, BDPAGETYPE: 1, BDUSERID: 0, BDQID: 0xaaa869770d8d5dcd, Set-Cookie: BDSVRTM=2; path=/, Set-Cookie: H_PS_PSSID=3361_2777_1465_2975_3109; path=/; domain=.baidu.com, Set-Cookie: BAIDUID=C0C2EAA4B1805EF21EE097E2C6A3D448:FG=1; expires=Tue, 17-Sep-43 01:43:44 GMT; path=/; domain=.baidu.com, P3P: CP=" OTI DSP COR IVA OUR IND COM "]
			
			//gCurCookieStore (formatted ouput) value:
			/*{
			    [version: 0][name: BAIDUID][value: C0C2EAA4B1805EF21EE097E2C6A3D448:FG=1][domain: .baidu.com][path: /][expiry: Thu Sep 17 09:43:44 CST 2043]=java.lang.Object@55ba1c2b,
			    [version: 0][name: BDSVRTM][value: 2][domain: www.baidu.com][path: /][expiry: null]=java.lang.Object@55ba1c2b,
			    [version: 0][name: H_PS_PSSID][value: 3361_2777_1465_2975_3109][domain: .baidu.com][path: /][expiry: null]=java.lang.Object@55ba1c2b
			}*/
		} catch (ClientProtocolException cpe) {
				// TODO Auto-generated catch block
				cpe.printStackTrace();
			} catch (IOException ioe) {
				// TODO Auto-generated catch block
				ioe.printStackTrace();
			}
		
    	return response;
    }

    /** Get response from url  */
    public HttpResponse getUrlResponse(String url)
    {
    	return getUrlResponse(url, null, null, 0);
    }

    /** Get response html from url, headerDict, html charset, postDict */
    public String getUrlRespHtml(
    							String url,
    							List<NameValuePair> headerDict,
    							List<NameValuePair> postDict,
									int timeout,
									String htmlCharset
		)
    {
    	// init
    	String respHtml = "";
    	String defaultCharset = "UTF-8";
    	if((null == htmlCharset) || htmlCharset.isEmpty())
    	{
    		htmlCharset = defaultCharset;
    	}
    	//init 
    	//HttpClient httpClient = new DefaultHttpClient();
    	//DefaultHttpClient httpClient = new DefaultHttpClient();
    	//HttpUriRequest request;
    	
    	//headerParams.setParameter(CoreProtocolPNames.HTTP_CONTENT_CHARSET, htmlCharset);
			try{
				HttpResponse response = getUrlResponse(url, headerDict, postDict, timeout);
				
				if(response.getStatusLine().getStatusCode()==HttpStatus.SC_OK){
					HttpEntity respEnt = response.getEntity();

					respHtml = EntityUtils.toString(respEnt, htmlCharset);
				}	        
			} catch (ClientProtocolException cpe) {
				// TODO Auto-generated catch block
				cpe.printStackTrace();    
			} catch (IOException ioe) {
				// TODO Auto-generated catch block
				ioe.printStackTrace();
			}
		
    	return respHtml;
    }
    
    public String getUrlRespHtml(String url, List<NameValuePair> headerDict, List<NameValuePair> postDict)
    {
    	return getUrlRespHtml(url, headerDict, postDict, 0, "");
    }
    
    public String getUrlRespHtml(String url, String htmlCharset)
    {
    	return getUrlRespHtml(url, null, null, 0, htmlCharset);
    }
    
    public String getUrlRespHtml(String url)
    {
    	String defaulCharset = "UTF-8";
    	return getUrlRespHtml(url, defaulCharset);
    }
    
    public interface UpdateProgressCallback
    {
        // This is just a regular method so it can return something or
        // take arguments if you like.
        public void updateProgress(long currentSize, long totalSize);
    }

    /**
     *  download file from file url
     * eg:
     * http://m5.songtaste.com/201212211424/2e8a8a85d93f56370d7fd96b5dc6ff23/5/5c/5cf23a97cef6fad6a464eb506c409dbd.mp3
     * with header: Referer=http://songtaste.com/
     *  */
    public Boolean downlodFile(String url, File fullFilename, List<NameValuePair> headerDict, UpdateProgressCallback updateProgressCallbak)
    {
    	Boolean downloadOk = Boolean.FALSE;
    	
    	HttpResponse response = getUrlResponse(url, headerDict, null, 0);

			if(response.getStatusLine().getStatusCode()==HttpStatus.SC_OK){
				HttpEntity respEnt = response.getEntity();

				System.out.println("isChunked" + respEnt.isChunked());
				System.out.println("Streaming" + respEnt.isStreaming());
				
				Boolean isStream = respEnt.isStreaming();
				if(isStream){
					try {
						InputStream fileInStream = respEnt.getContent();
						
						FileOutputStream fileOutStream = new FileOutputStream(fullFilename);
						
						long totalSize = respEnt.getContentLength();
						byte[] tmpBuf = new byte[8192];
						int bufLen = 0;
						long downloadedSize = 0;
						while( (bufLen = fileInStream.read(tmpBuf)) > 0 ) {
							fileOutStream.write(tmpBuf,0, bufLen);
							downloadedSize += bufLen;
							
							//System.out.println(Long.toString((downloadedSize/totalSize)*100)+"%");
							//System.out.println(Long.toString((downloadedSize*100)/totalSize)+"%");
							updateProgressCallbak.updateProgress(downloadedSize, totalSize);
						}
						fileOutStream.close();
						downloadOk = Boolean.TRUE;
					} catch (IllegalStateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}

			return downloadOk;
    }

    /**
     *  none header version of downlodFile
     *  */
    public String downlodFile(String url, String fullFilename)
    {
    	return downlodFile(url, fullFilename);
    }

}
