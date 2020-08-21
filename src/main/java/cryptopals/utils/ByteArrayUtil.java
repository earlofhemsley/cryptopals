package cryptopals.utils;

import java.util.Random;

/**
 * A util for manipulating byte arrays, or
 * a util where common actions regarding byte arrays
 * not adequately served by other packages are contained
 */
public class ByteArrayUtil {
    private ByteArrayUtil() {
        throw new AssertionError("Cannot instantiate");
    }

    public static byte[] sliceByteArray(byte[] original, int start, int length) {
        byte[] slice = new byte[length];
        for (int i = 0; i < length; i++) {
            if (start + i < original.length) {
                slice[i] = original[start + i];
            }
        }

        return slice;
    }

    public static byte[] randomBytes(int length) {
        byte[] retVal = new byte[length];
        Random r = new Random();
        r.nextBytes(retVal);
        return retVal;
    }

    public static byte[] groupByteNegation(byte[] toNegate) {
        var retval = new byte[toNegate.length];
        for (int i = 0; i < toNegate.length; i++) {
            retval[i] = (byte) (~toNegate[i] & 0xFF);
        }
        return retval;
    }

}
