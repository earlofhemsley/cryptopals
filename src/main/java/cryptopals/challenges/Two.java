package cryptopals.challenges;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Two {
    public static String fixedXOR(String hexString1, String hexString2) throws DecoderException {
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
}
