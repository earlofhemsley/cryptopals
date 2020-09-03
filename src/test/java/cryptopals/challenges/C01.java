package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.util.Base64;

/**
 * Convert hex to base64
 * The string:
 *
 * 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 * Should produce:
 *
 * SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
 * So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
 *
 * Cryptopals Rule
 * Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
 * @throws DecoderException
 */
public class C01 {

    @Test
    public void oneTest() throws DecoderException {
        String input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        byte[] hexBytes = Hex.decodeHex(input);
        String result = Base64.getEncoder().encodeToString(hexBytes);
        assertEquals("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", result);
        String reconverted = Hex.encodeHexString(Base64.getDecoder().decode(result));
        assertEquals(input, reconverted);
    }

}
