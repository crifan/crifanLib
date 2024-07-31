/*
	File: crifanLibOkHttp.java
	Function: crifan's common java's OkHttp network related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/crifanLibOkHttp.java
	Updated: 20240731
*/

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import crifanLib;

public class crifanLibOkHttp {

	public crifanLibOkHttp()
	{
	}

	/**
	 * do/execute http POST request, body format is JSON (not Form)
	 * @param url url
	 * @param bodyJsonStr post body string
	 * @return the response
	 */
	public static Response doPost(String url, String bodyJsonStr) throws IOException {
		// Utils.logD(String.format("doPost: url=%s, bodyJsonStr=%s", url, bodyJsonStr));
		RequestBody reqBody = RequestBody.create(MEDIA_TYPE_JSON, bodyJsonStr);
		// Utils.logD(String.format("reqBody=%s", reqBody));
		Request request = new Request.Builder()
						.url(url)
						.post(reqBody)
						.build();
		// Utils.logD(String.format("request=%s", request));
		Response response = client.newCall(request).execute();
		// Utils.logD(String.format("response=%s", response));
		return response;
	}

	/**
	 * do/execute http POST request, body format is JSON (not Form)
	 * @param url url
	 * @param paramDict body parameter dict/map
	 * @return the response
	 */
	public static Response doPost(String url, Map<String, String> paramDict) throws IOException {
		// Utils.logD(String.format("doPost: url=%s, paramDict=%s", url, paramDict));
		String postJsonStr = crifanLib.mapToJsonStr(paramDict);
		// Utils.logD(String.format("postJsonStr=%s", postJsonStr));
		return doPost(url, postJsonStr);
	}
}
