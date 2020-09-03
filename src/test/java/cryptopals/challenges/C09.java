package cryptopals.challenges;

import static cryptopals.utils.PKCS7Util.applyPadding;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

/**
 * Implement PKCS#7 padding
 *
 * A block cipher transforms a fixed-sized block (usually 8 or 16 bytes)
 * of plaintext into ciphertext. But we almost never want to transform a single block;
 * we encrypt irregularly-sized messages.
 *
 * One way we account for irregularly-sized messages is by padding,
 * creating a plaintext that is an even multiple of the blocksize.
 * The most popular padding scheme is called PKCS#7.
 *
 * So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
 *
 * For instance,
 *
 * "YELLOW SUBMARINE"
 * ... padded to 20 bytes would be:
 *
 * "YELLOW SUBMARINE\x04\x04\x04\x04"
 */
public class C09 {
    @Test
    public void testChallenge09() {
        String testString = "YELLOW SUBMARINE";
        byte[] result = applyPadding(testString.getBytes(), 20);
        String expected = testString + (char) 4 + (char) 4 + (char) 4 + (char) 4;
        assertArrayEquals(expected.getBytes(), result);

        result = applyPadding(testString.getBytes(), 3);
        expected = testString + (char) 2 + (char) 2;
        assertArrayEquals(expected.getBytes(), result);

        result = applyPadding(testString.getBytes(), 4);
        expected = testString + (char) 4 + (char) 4 + (char) 4 + (char) 4;
        assertArrayEquals(expected.getBytes(), result);
    }
}
