/*
	File: ListUtil.java
	Function: crifan's common java's List related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/ListUtil.java
	Updated: 20240807
*/

import java.util.List;

public class ListUtil {

    // for  [a, b, c] and [c, b, a, b], here isListEqual -> true = means equal
    // if you think is not equal -> then should modify isListEqual's code logic
    public static boolean isListEqual(List list1, List list2){
//        boolean isEqual = CollectionUtils.isEqualCollection(list1, list2));
        boolean isEqual = list1.containsAll(list2) && list2.containsAll(list1);
        return isEqual;
    }
}
