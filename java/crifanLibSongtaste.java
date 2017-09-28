/**
 * [File]
 * crifanLibSongtaste.java
 * 
 * [Function]
 * 1. implement common songtaste functions
 * 
 * [Version]
 * v1.0
 * 2013-04-27
 * 
 * [History]
 * 1. add extract title, singer, real address
 */

package crifan.com;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.ArrayList;

import org.apache.http.NameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.message.BasicNameValuePair;

import crifan.com.crifanLib.UpdateProgressCallback;

public class crifanLibSongtaste {
	public class albumInfo
	{
		public String url;
		public String name;
		public String author;
	};
	
	public class songInfo {
		public String id;       // 2224853
		public String url;      // http://www.songtaste.com/song/2224853/
		public String realAddr; // http://m6.songtaste.com/201204131040/90ee3460a764e82816d5233fe2acaccc/6/62/625c4102d5a2f89f614d874b2c2ca402.mp3
		public String artist;   // DJ OKAWARI
		public String title;    // Flower Dance
		public String suffix;   // .mp3
		public String storedName; //Flower Dance - DJ OKAWARI.mp3
		
		//public string recommender;// loveqian1314
		//public string recommenderId;// 3334687
		//public string recommenderUrl;// http://songtaste.com/user/3334687/
		
		songInfo()
		{
			id = "";
			url = "";
			realAddr = "";
			artist = "";
			title = "";
			suffix = "";
			storedName = "";
		}
	};
	
	crifanLib crifanLib = null;
	
	/* 
	 * GB18030 is superset of GBK
	 * GBK is superset of GB2312
	 * */
	static final String  stHtmlCharset = "GB18030";
	
	public crifanLibSongtaste()
	{

		crifanLib = new crifanLib();
		
	};
	
	
    /**
     * None pattern version of  extractSingleStr
     * */
    public Boolean extractSingleStr(String pattern, String extractFrom, StringBuilder extractedStr)
    {
    	return crifanLib.extractSingleStr(pattern, extractFrom, 0, extractedStr);
    }
   
    /** Extract music title from html of songtaste music url */
    public Boolean stExtractMusicTitle(String html, StringBuilder sbExtractedTitle)
    {
    	return crifanLib.extractSingleStr("<p\\s+class=\"mid_tit\">(.+?)</p>", html, sbExtractedTitle);
    }
    
    /**
     *  Extract music singer from html of songtaste music url
     *  Note: special: http://www.songtaste.com/song/809103/, no singer, got empty string
     *   */
    public Boolean stExtractMusicSinger(String html, StringBuilder sbExtractedSinger)
    {
    	return crifanLib.extractSingleStr("<h1\\s+class=\"h1singer\">(.*?)</h1>", html, sbExtractedSinger);
    }
    
    /** get real music address from songtaste music url */
    public Boolean stGetRealAddressFromUrl(String stUrl, StringBuilder sbMusicRealAddress) {
    	Boolean gotReadAddr = Boolean.FALSE;
    	String realAddr = "";
    	
    	String respHtml = crifanLib.getUrlRespHtml(stUrl, stHtmlCharset); 

    	// 1. extract title
    	//<p class="mid_tit">我的爱与你分享</p><p></p>
    	StringBuilder sbExtractedTitle = new StringBuilder();
    	if(stExtractMusicTitle(respHtml, sbExtractedTitle))
    	{
    		//System.out.println(sbExtractedTitle);
    		
    		// 2. extract singer
    		//<h1 class="h1singer">未知</h1>
    		StringBuilder sbExtractedSinger = new StringBuilder();
    		if(stExtractMusicSinger(respHtml, sbExtractedSinger))
    		{
    			String extractedSinger = sbExtractedSinger.toString();
    			//special: http://www.songtaste.com/song/809103/, no singer
    			if(extractedSinger == "")
    			{
    				extractedSinger = "Unknown Singer";
    			}
    			
    			// 3. get song real address
                //<a href="javascript:playmedia1('playicon','player', '5bf271ccad05f95186be764f725e9aaf07e0c7791a89123a9addb2a239179e64c91834c698a9c5d82f1ced3fe51ffc51', '355', '68', 'b3a7a4e64bcd8aabe4cabe0e55b57af5', 'http://m3.', '3015123',0);ListenLog(3015123, 0);">
                //special http://www.songtaste.com/song/2428041/ contain:
                //<a href="javascript:playmedia1('playicon','player', 'cachefile33.rayfile.com/12f1/zh-cn/download/d1e8d86a0a9880f697aee789f27383db/preview', '355', '68', 'b3a7a4e64bcd8aabe4cabe0e55b57af5', 'http://224.', '2428041',0);ListenLog(2428041, 0);">
    			String mediaPatStr = "javascript:playmedia1\\('playicon','player', '([^']+)', '\\d+', '\\d+', '(\\w+)', '(.+?)', '(\\d+)',\\d+\\);";
    	    	Pattern mediaP = Pattern.compile(mediaPatStr);
    	    	Matcher foundMedia = mediaP.matcher(respHtml);
    	    	Boolean bFoundMedia = foundMedia.find();
    	    	if(bFoundMedia)
    	    	{
    	    		String str 			= foundMedia.group(1);
    	    		String urlPref 	= foundMedia.group(2);
    	    		String keyStr 	= foundMedia.group(3);
    	    		String sid 			= foundMedia.group(4);
    	    		
    	    		if(str.contains("/"))
    	    		{
                        //cachefile33.rayfile.com/12f1/zh-cn/download/d1e8d86a0a9880f697aee789f27383db/preview
                        //to get the suffix
    	    			String suffix = "";
    	    			String mainJsUrl = "http://image.songtaste.com/inc/main.js";
    	    			String respHtmlMainJs = crifanLib.getUrlRespHtml(mainJsUrl);
                        //		case "b3a7a4e64bcd8aabe4cabe0e55b57af5":
	                    //          return ".mp3";
    	    			String suffixPatStr = "\"" + keyStr + "\":.+?return\\s+\"(\\.\\w+)\";";
    	    			
//    	    			Pattern suffixP = Pattern.compile(suffixPatStr, Pattern.DOTALL);
//    	    			Matcher foundSuffix = suffixP.matcher(respHtmlMainJs);
//    	    			Boolean bFoundSuffix = foundMedia.find();
//    	    			if(bFoundSuffix)
//    	    			{
//    	    				suffix = foundSuffix.group(1);
//    	    			}
    	    			
    	    			StringBuilder sbExtractedSuffix= new StringBuilder();
    	    			if(crifanLib.extractSingleStr(suffixPatStr, respHtmlMainJs, Pattern.DOTALL, sbExtractedSuffix))
    	    			{
    	    				suffix = sbExtractedSuffix.toString();
    	    				realAddr = urlPref + str + suffix;
    	    			}
    	    		}
    	    		else
    	    		{
    	    			//5bf271ccad05f95186be764f725e9aaf07e0c7791a89123a9addb2a239179e64c91834c698a9c5d82f1ced3fe51ffc51
    	    			
    	    			//header
    	    			HttpParams headrDict = new BasicHttpParams();
    	    			headrDict.setParameter("x-requested-with", "XMLHttpRequest");
    	    			
    	    			//post data
    	    			List<NameValuePair> postDict = new ArrayList<NameValuePair>(); 
    	    			postDict.add(new BasicNameValuePair("str", str));
    	    			postDict.add(new BasicNameValuePair("sid", sid));
    	    			postDict.add(new BasicNameValuePair("t", "0"));
    	    			String getRealAddrUrl = "http://songtaste.com/time.php";
    	    			realAddr = crifanLib.getUrlRespHtml(getRealAddrUrl, headrDict, stHtmlCharset, postDict);
    	    		}
    	    	}//bFoundMedia
    		}//stExtractMusicSinger
    	}//stExtractMusicTitle
    			
		if(realAddr != ""){
			sbMusicRealAddress.append(realAddr);
			gotReadAddr = Boolean.TRUE;
		}
		
		return gotReadAddr;
    }
    
    public Boolean stDownloadFromUrl(String strSongUrl, File fullFilename, UpdateProgressCallback updateProgressCallbak)
    {
    	Boolean downloadOk = Boolean.FALSE;
    	
    	StringBuilder sbMusicRealAddress = new StringBuilder();
    	if(stGetRealAddressFromUrl(strSongUrl, sbMusicRealAddress))
    	{
			HttpParams headrDict = new BasicHttpParams();
			headrDict.setParameter("Referer", "http://songtaste.com/");
    		
    		crifanLib.downlodFile(sbMusicRealAddress.toString(), fullFilename, headrDict, updateProgressCallbak);
    	}
    	
    	return downloadOk;
    }

}