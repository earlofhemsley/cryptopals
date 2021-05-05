package cryptopals.utils;

import java.nio.charset.StandardCharsets;
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
        //don't use array copy to be length safe
        for (int i = 0; i < length; i++) {
            if (start + i < original.length) {
                slice[i] = original[start + i];
            }
        }

        return slice;
    }

    public static byte[] sliceEnd(byte[] original, int lengthFromEnd) {
        byte[] slice = new byte[lengthFromEnd];
        System.arraycopy(original, original.length-lengthFromEnd, slice, 0, lengthFromEnd);
        return slice;
    }

    public static byte[] randomBytes(int length) {
        return randomBytes(length, null);
    }

    public static byte[] randomBytes(int length, final String seed) {
        byte[] retVal = new byte[length];
        Random r = seed == null ? new Random(System.currentTimeMillis()) : new Random(seed.hashCode());
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

    public static byte[][] transposeByteMatrix(final byte[][] matrix) {
        if (matrix.length == 0) {
            return new byte[0][0];
        }
        final int matrixHeight = matrix.length;
        final int matrixWidth = matrix[0].length;

        byte[][] transposed = new byte[matrixWidth][matrixHeight];

        for (int y = 0; y < matrixHeight; y++) {
            if (matrix[y].length != matrixWidth) {
                throw new IllegalArgumentException("all rows in matrix must be equal width");
            }
            for (int x = 0; x < matrixWidth; x++) {
                transposed[x][y] = matrix[y][x];
            }
        }
        return transposed;
    }

}
