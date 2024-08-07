/*
	File: JsonMapUtil.java
	Function: crifan's common java's json & Map related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/JsonMapUtil.java
	Updated: 20240807
*/

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class JsonMapUtil {

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
//        Utils.logD(String.format("strToJson: jsonStr=%s", jsonStr));
        try {
            jsonObj = new JSONObject(jsonStr);
//            Utils.logD(String.format("strToJson: jsonObj=%s", jsonObj));
        }catch (JSONException err){
            // Utils.logD(String.format("strToJson failed: %s", err.toString()));
        }
        return jsonObj;
    }

    public static JSONObject mergeJson(JSONObject json1, JSONObject json2) throws JSONException {
        JSONObject mergedJson = new JSONObject();
        JSONObject[] jsonObjList = new JSONObject[] { json1, json2 };
        // Utils.logD(String.format("jsonObjList=%s", jsonObjList.toString()));
        for (JSONObject jsonObj : jsonObjList) {
            Iterator keyIterator = jsonObj.keys();
            // Utils.logD(String.format("keyIterator=%s", keyIterator));
            while (keyIterator.hasNext()) {
                String curKey = (String)keyIterator.next();
                Object curValue = jsonObj.opt(curKey);
                // Utils.logD(String.format("curKey=%s, curValue=%s", curKey, curValue));
                mergedJson.put(curKey, curValue);
            }
//            Set<Map.Entry<String,Object>> jsonEntrySet = jsonObj.en
        }
        return mergedJson;
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
                value = jsonToMap((JSONObject)value);
            }
            jsonMap.put(key, value);
        }
        return jsonMap;
    }

    // flatten json to map == remove embedded json sub field
    // temp: no consider process Json Array
    public static Map<String, Object> flattenJsonToMap(JSONObject jsonObj) {
        Map<String, Object> flattenedMap = new HashMap<String, Object>();
        Iterator<String> keys = jsonObj.keys();
        while(keys.hasNext()) {
            String key = keys.next();
            Object value = null;
            try {
                value = jsonObj.get(key);
            } catch (JSONException jsonErr) {
                Utils.logE(String.format("Error %s when get %s's value", jsonErr, key));
            }

            if (value instanceof JSONObject) {
                Map<String, Object> flattenedSubMap = flattenJsonToMap((JSONObject)value);
//                Utils.logD(String.format("flattenedSubMap=%s", flattenedSubMap));
                flattenedMap.putAll(flattenedSubMap);
            } else {
                flattenedMap.put(key, value);
            }
        }
//        Utils.logD(String.format("jsonObj=%s -> flattenedMap=%s", jsonObj, flattenedMap));
        return flattenedMap;
    }


    // sub field is json string -> convert to json/map then merge to parent map
    public static Map<String, Object> flattenSubFieldJsonStr(Map<String, Object> originParentMap, String subFieldKey){
//        Utils.logD(String.format("originParentMap=%s, subFieldKey=%s", originParentMap, subFieldKey));

        Map<String, Object> flattenedParentMap = new HashMap<>(originParentMap);
        if (flattenedParentMap.containsKey(subFieldKey)){
            Object subFieldValObj = flattenedParentMap.get(subFieldKey);
//            Utils.logD(String.format("subFieldValObj=%s", subFieldValObj));
            if (subFieldValObj instanceof String) {
                String subFieldValJsonStr = subFieldValObj.toString();
//                Utils.logD(String.format("subFieldValJsonStr=%s", subFieldValJsonStr));
                JSONObject subFieldJson = JsonMapUtil.strToJson(subFieldValJsonStr);
//                Utils.logD(String.format("subFieldJson=%s", subFieldJson));
                if (null != subFieldJson) {
                    Map<String, Object> flattenedSubFieldMap = JsonMapUtil.flattenJsonToMap(subFieldJson);
//                    Utils.logD(String.format("flattenedSubFieldMap=%s", flattenedSubFieldMap));
                    flattenedParentMap.remove(subFieldKey);
//                    Utils.logD(String.format("flattenedParentMap=%s", flattenedParentMap));
                    flattenedParentMap.putAll(flattenedSubFieldMap);
                }
            }
        } else {
            // Utils.logD(String.format("Map not contain key: %s", subFieldKey));
        }
        // Utils.logD(String.format("After flatten %s -> flattenedParentMap=%s", subFieldKey, flattenedParentMap));
        return flattenedParentMap;
    }

}
