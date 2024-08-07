/*
	File: UrlUtil.java
	Function: crifan's common java's url related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/UrlUtil.java
	Updated: 20240807
*/

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class UrlUtil {

    /**
     * Parse out query string map/dict from url
     * @param url url
     * @return query string map/dict
     */
    public static Map<String, String> parseUrlQsPara(String url) throws URISyntaxException, UnsupportedEncodingException {
//        Utils.logD(String.format("parseUrlQsPara: url=%s", url));
        Map<String, String> urlQsParaDict = new HashMap<String, String>();
        URI uri = new URI(url);
//        Utils.logD(String.format("uri=%s", uri));
        String scheme = uri.getScheme();
        String host = uri.getHost();
//        Utils.logD(String.format("scheme=%s, host=%s", scheme, host));
        String rawQuery = uri.getRawQuery();
//        Utils.logD(String.format("rawQuery=%s", rawQuery));
//        String decodedQuery = null;
//        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
//            decodedQuery = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8);
//        }
        String decodedQuery = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8.toString());
//        Utils.logD(String.format("decodedQuery=%s", decodedQuery));
//        String[] paraList = rawQuery.split("&");
        String[] paraList = decodedQuery.split("&");
//        Utils.logD(String.format("paraList=%s", paraList.toString()));
        for (String eachPart : paraList) {
//            Utils.logD(String.format("eachPart=%s", eachPart));
            String paraKey = "";
            String paraValue = "";
            if (eachPart.contains("=")){
                String[] paraKeyValueList = eachPart.split("=");
                paraKey = paraKeyValueList[0];
                paraValue = paraKeyValueList[1];
            } else {
                paraKey = eachPart;
                paraValue = "";
            }
//            Utils.logD(String.format("paraKey=%s, paraValue=%s", paraKey, paraValue));
            urlQsParaDict.put(paraKey, paraValue);
        }
//        Utils.logD(String.format("urlQsParaDict=%s", urlQsParaDict));
        return urlQsParaDict;
    }

}
