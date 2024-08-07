/*
	File: ByteUtil.java
	Function: crifan's common java's Bytes related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/ByteUtil.java
	Updated: 20240807
*/

public class ByteUtil {

    public static int hexCharToInt(char ch) {
        if ('0' <= ch && ch <= '9') {
            return ch - '0';
        }
        if ('A' <= ch && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if ('a' <= ch && ch <= 'f') {
            return ch - 'a' + 10;
        }
        return -1;
    }

    public static byte[] hexStrToBytes(String s) {
        final int len = s.length();

        // "111" is not a valid hex encoding.
        if (len % 2 != 0) {
            throw new IllegalArgumentException("hexBinary needs to be even-length: " + s);
        }

        byte[] parsedBytes = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int h = hexCharToInt(s.charAt(i));
            int l = hexCharToInt(s.charAt(i + 1));
            if (h == -1 || l == -1) {
                throw new IllegalArgumentException("contains illegal character for hexBinary: " + s);
            }

            parsedBytes[i / 2] = (byte) (h * 16 + l);
        }

        return parsedBytes;
    }

}
