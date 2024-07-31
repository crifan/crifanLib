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

public class crifanLibOkHttp {

	public crifanLibOkHttp()
	{
	}

	public static Response doPost(String url, String postBodyStr) throws IOException {
		// Utils.logD(String.format("doPost: url=%s, postBodyStr=%s", url, postBodyStr));
		RequestBody reqBody = RequestBody.create(MEDIA_TYPE_JSON, postBodyStr);
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

	public static Response doPost(String url, Map<String, String> paramDict) throws IOException {
		// Utils.logD(String.format("doPost: url=%s, paramDict=%s", url, paramDict));
		String postJsonStr = Utils.mapToJsonStr(paramDict);
		// Utils.logD(String.format("postJsonStr=%s", postJsonStr));
		return doPost(url, postJsonStr);
	}
}
