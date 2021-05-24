package cryptopals.challenges.sec02;

import static cryptopals.utils.PKCS7Util.stripPadding;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cryptopals.exceptions.BadPaddingRuntimeException;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;

/**
 * PKCS#7 padding validation
 * Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
 *
 * The string:
 *
 * "ICE ICE BABY\x04\x04\x04\x04"
 * ... has valid padding, and produces the result "ICE ICE BABY".
 *
 * The string:
 *
 * "ICE ICE BABY\x05\x05\x05\x05"
 * ... does not have valid padding, nor does:
 *
 * "ICE ICE BABY\x01\x02\x03\x04"
 * If you are writing in a language with exceptions, like Python or Ruby, make your function throw
 * an exception on bad padding.
 *
 * Crypto nerds know where we're going with this. Bear with us.
 */
public class C15 {
    @Test
    public void testChallenge15() throws BadPaddingException {
        assertArrayEquals("ICE ICE BABY".getBytes(), stripPadding(generatePaddingSample(new byte[] {4,4,4,4})));
        assertThrows(BadPaddingRuntimeException.class, () -> stripPadding(generatePaddingSample(new byte[] {5,5,5,5})));
        assertThrows(BadPaddingRuntimeException.class, () -> stripPadding(generatePaddingSample(new byte[] {1,2,3,4})));
    }

    private static byte[] generatePaddingSample(byte[] paddingBytes) {
        String sb = "ICE ICE BABY" +
                new String(paddingBytes);
        return sb.getBytes();
    }
}
