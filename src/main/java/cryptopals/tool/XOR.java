package cryptopals.tool;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayOutputStream;

/**
 * A tool relating to XOR operations for encryption/decryption
 */
public class XOR {
    /**
     * single-character encryption. this is the solution to challenge 2
     * @param hexString1
     * @param hexString2
     * @return
     * @throws DecoderException
     */
    public String hexStringFixedXor(String hexString1, String hexString2) throws DecoderException {
        byte[] input1 = Hex.decodeHex(hexString1);
        byte[] input2 = Hex.decodeHex(hexString2);

        int looplimit = Math.min(input1.length, input2.length);

        byte[] result = new byte[looplimit];

        for (int i = 0; i < looplimit; i++) {
            int left = Byte.toUnsignedInt(input1[i]);
            int right = Byte.toUnsignedInt(input2[i]);
            int xordResult = left ^ right;
            result[i] = (byte) (xordResult & 0xFF);
        }

        return String.valueOf(Hex.encodeHex(result));
    }

    /**
     * xor's a byte array against a single integer key
     * @param input
     * @param key
     * @return
     */
    public byte[] singleKeyXOR(byte[] input, int key) {
        byte[] decrypted = new byte[input.length];
        for(int i = 0; i < decrypted.length; i++) {
            decrypted[i] = (byte) ((int) input[i] ^ key);
        }
        return decrypted;
    }

    public char[] singleKeyXORToCharArray(byte[] input, int key) {
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
     * @param input
     * @param key
     * @return
     */
    public byte[] multiByteXOR(byte[] input, byte[] key) {
        byte[] xord = new byte[input.length];
        for(int i = 0; i < xord.length; i++) {
            xord[i] = (byte) (input[i] ^ key[i % key.length]);
        }
        return xord;
    }
}
