package cryptopals.tool;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * A tool relating to XOR operations for encryption/decryption
 */
//TODO: make this a static util class
public class XOR {
    private XOR() {
        throw new Error("do not instantiate");
    }

    /**
     * single-character encryption. this is the solution to challenge 2
     * @param hexString1 first hex string
     * @param hexString2 second hex string
     * @return the result of a xor on both strings
     * @throws DecoderException if the hex strings cannot be decoded as such
     */
    public static String hexStringFixedXOR(String hexString1, String hexString2) throws DecoderException {
        byte[] input1 = Hex.decodeHex(hexString1);
        byte[] input2 = Hex.decodeHex(hexString2);

        int loopLimit = Math.min(input1.length, input2.length);

        byte[] result = new byte[loopLimit];

        for (int i = 0; i < loopLimit; i++) {
            int left = Byte.toUnsignedInt(input1[i]);
            int right = Byte.toUnsignedInt(input2[i]);
            int xorResult = left ^ right;
            result[i] = (byte) (xorResult & 0xFF);
        }

        return String.valueOf(Hex.encodeHex(result));
    }

    /**
     * performs an XOR on a byte array against a single integer key
     * @param input the input
     * @param key the key for the XOR
     * @return the result of the XOR
     */
    public static byte[] singleKeyXOR(byte[] input, int key) {
        byte[] decrypted = new byte[input.length];
        for(int i = 0; i < decrypted.length; i++) {
            decrypted[i] = (byte) ((int) input[i] ^ key);
        }
        return decrypted;
    }

    public static char[] singleKeyXORToCharArray(byte[] input, int key) {
        final byte[] result = singleKeyXOR(input, key);
        final char[] returnValue = new char[result.length];
        for (int i = 0; i < result.length; i++) {
            returnValue[i] = (char) result[i];
        }
        return returnValue;
    }

    /**
     * xor's each successive byte of one byte array against each successive byte
     * of a key byte array.
     * @param input the multibyte input
     * @param key the multibyte key
     * @return the result of the XOR
     */
    public static byte[] multiByteXOR(byte[] input, byte[] key) {
        byte[] xorResult = new byte[input.length];
        for(int i = 0; i < xorResult.length; i++) {
            xorResult[i] = (byte) (input[i] ^ key[i % key.length]);
        }
        return xorResult;
    }
}
