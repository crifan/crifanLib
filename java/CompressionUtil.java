/*
	File: CompressionUtil.java
	Function: crifan's common java's compress & decompress related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/java/CompressionUtil.java
	Updated: 20240808
*/

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class CompressionUtil {

    public static boolean isCompressed(final byte[] compressed) {
        return (compressed[0] == (byte) (GZIPInputStream.GZIP_MAGIC))  &&
                (compressed[1] == (byte) (GZIPInputStream.GZIP_MAGIC >> 8));
    }

    public static byte[] compress(final String str) throws IOException, IOException {
        if ((str == null) || (str.length() == 0)) {
            return null;
        }

        ByteArrayOutputStream byteArrOutStream = new ByteArrayOutputStream();
        GZIPOutputStream gzipOutStream = new GZIPOutputStream(byteArrOutStream);
        gzipOutStream.write(str.getBytes(StandardCharsets.UTF_8));
        gzipOutStream.flush();
        gzipOutStream.close();
        return byteArrOutStream.toByteArray();
    }

    public static String decompressToStr(final byte[] compressed) throws IOException {
        final StringBuilder outStr = new StringBuilder();
        if ((compressed == null) || (compressed.length == 0)) {
            return "";
        }
        if (isCompressed(compressed)) {
            final GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
            final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(gis, StandardCharsets.UTF_8));

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                outStr.append(line);
            }
        } else {
            outStr.append(compressed);
        }
        return outStr.toString();
    }

    public static byte[] decompressToBytes(byte[] gzipBytes) throws IOException {
        // With 'gzip' being the compressed buffer
        ByteArrayInputStream inputBytes = new ByteArrayInputStream(gzipBytes);
        GZIPInputStream inputGzipStream = new GZIPInputStream(inputBytes);
        ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();

        int res = 0;
        int bufSize = 512 * 1024;
        byte buf[] = new byte[bufSize];
        while (res >= 0) {
            res = inputGzipStream.read(buf, 0, buf.length);
            if (res > 0) {
                outputBytes.write(buf, 0, res);
            }
        }
        byte uncompressedBytes[] = outputBytes.toByteArray();
        return uncompressedBytes;
    }

    public static String decodeGzipHexStr(String gzipHexStr) throws IOException {
        byte[] bodyBytes = ByteUtil.hexStrToBytes(gzipHexStr);
        Utils.logD(String.format("bodyBytes=%s", bodyBytes));
        byte[] uncompressedBodyBytes = CompressionUtil.decompressToBytes(bodyBytes);
        Utils.logD(String.format("uncompressedBodyBytes=%s", uncompressedBodyBytes));
        String decodedStr = new String(uncompressedBodyBytes, StandardCharsets.UTF_8);
        Utils.logD(String.format("decodedStr=%s", decodedStr));
        return decodedStr;
    }

}
