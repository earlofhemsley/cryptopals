package cryptopals.challenges;

import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class One {
    static String convertHexToBase64(String hexInput) throws DecoderException {
        byte[] hextBytes = Hex.decodeHex(hexInput);
        return Base64.getEncoder().encodeToString(hextBytes);
    }
}
