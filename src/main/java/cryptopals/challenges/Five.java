package cryptopals.challenges;

import cryptopals.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Five {
    private static byte[] key = "ICE".getBytes();

    public static String repeatingKeyEncrypt(String toEncrypt) {
       byte[] result = Utils.multiByteXOR(toEncrypt.getBytes(), key);
       return String.valueOf(Hex.encodeHex(result));
    }

    public static String repeatingKeyDecrypt(String toDecrypt) throws DecoderException {
        byte[] hexDecoded = Hex.decodeHex(toDecrypt);
        byte[] decrypted = Utils.multiByteXOR(hexDecoded, key);
        StringBuilder result = new StringBuilder();
        for (byte b : decrypted) {
            result.append((char)b);
        }
        return result.toString();
    }
}
