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

    /**
     * take an int and convert it to a byte array. The conversion retains left-to-right-ness of the bits.
     * The most significant bits in the int are in the first element of the returned byte array.
     * The least significant bits in the int are in the last element of the returned byte array.
     *
     * This works by shifting the bits in an int by multiples of 8
     * and then leveraging the truncation that comes with typecasting
     * an int to a byte.
     *
     * @param i the int to be converted
     * @return byte array
     */
    public static byte[] intToByteArray(final int i) {
        final byte[] b = new byte[4];
        for (int j = 0; j <= 3; j++) {
            b[3-j] = (byte)(i >>> (8 * j));
        }
        return b;
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
