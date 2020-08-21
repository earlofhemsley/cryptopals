package cryptopals.sec01.util;

import cryptopals.utils.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Challenge5Tool {

    private final byte[] key;

    public Challenge5Tool(byte[] key) {
        this.key = key;
    }

    /**
     * encrypt a message with a repeating key. this is part of the solution to challenge five
     * @param toEncrypt
     * @return
     */
    public String repeatingKeyEncrypt(String toEncrypt) {
        byte[] result = new XOR().multiByteXOR(toEncrypt.getBytes(), key);
        return String.valueOf(Hex.encodeHex(result));
    }

    /**
     * decrypt a message with a repeating key. this is part of the solution to challenge five
     * @param toDecrypt
     * @return
     * @throws DecoderException
     */
    public String repeatingKeyDecrypt(String toDecrypt) throws DecoderException {
        byte[] hexDecoded = Hex.decodeHex(toDecrypt);
        byte[] decrypted = new XOR().multiByteXOR(hexDecoded, key);
        StringBuilder result = new StringBuilder();
        for (byte b : decrypted) {
            result.append((char)b);
        }
        return result.toString();
    }
}
