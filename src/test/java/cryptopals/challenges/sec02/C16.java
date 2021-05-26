package cryptopals.challenges.sec02;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.collect.Lists;
import cryptopals.tool.XOR;
import cryptopals.tool.sec02.Challenge16Tool;
import cryptopals.utils.ByteArrayUtil;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * CBC bitflipping attacks
 *
 * Generate a random AES key.
 *
 * Combine your padding code and CBC code to write two functions.
 *
 * The first function should take an arbitrary input string, prepend the string:
 *
 * "comment1=cooking%20MCs;userdata="
 * .. and append the string:
 *
 * ";comment2=%20like%20a%20pound%20of%20bacon"
 * The function should quote out the ";" and "=" characters.
 *
 * The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
 *
 * The second function should decrypt the string and look for the characters ";admin=true;"
 * (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples,
 * and look for the "admin" tuple).
 *
 * Return true or false based on whether the string exists.
 *
 * If you've written the first function properly, it should not be possible to provide
 * user input to it that will generate the string the second function is looking for.
 * We'll have to break the crypto to do that.
 *
 * Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
 *
 * You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
 *
 * Completely scrambles the block the error occurs in
 * Produces the identical 1-bit error(/edit) in the next ciphertext block.
 * Stop and think for a second.
 * Before you implement this attack, answer this question: why does CBC mode have this property?
 */
public class C16 {
    @Test
    public void testChallenge16() throws Exception {
        var key = ByteArrayUtil.randomBytes(16);
        var iv = ByteArrayUtil.randomBytes(16);
        var oracle = new Challenge16Tool(key, iv);
        //comment1=cooking|%20MCs;userdata=|AAAAAAAAAAAAAAAA|:admin<true:A<AA|;comment2=...
        String knownInput = "7admin9true7A9AA";
        String desired = ";admin=true;A=AA";
        assertEquals(16, knownInput.length());
        assertEquals(16, desired.length());

        final XOR xor = new XOR();
        byte[] xord = xor.multiByteXOR(knownInput.getBytes(), desired.getBytes());
        assertArrayEquals(desired.getBytes(), xor.multiByteXOR(knownInput.getBytes(), xord));
        assertArrayEquals(knownInput.getBytes(), xor.multiByteXOR(desired.getBytes(), xord));

        List<Integer> positionsOf12 = Lists.newArrayList(0, 11);
        List<Integer> positionsOf4 = Lists.newArrayList(6, 13);
        for (int i =0; i<xord.length; i++) {
            if (positionsOf4.contains(i)) {
                assertEquals(4, xord[i]);
            } else if (positionsOf12.contains(i)) {
                assertEquals(12, xord[i]);
            } else {
                assertEquals(0, xord[i]);
            }
        }

        //prepend with a block that we don't care if it gets scrambled
        knownInput = "AAAAAAAAAAAAAAAA" + knownInput;

        var cipherText = oracle.padAndEncrypt(knownInput);

        assertFalse(oracle.findAdminInCipherText(cipherText));

        var textToAlter = ByteArrayUtil.sliceByteArray(cipherText, 32, xord.length);
        var alteredText = xor.multiByteXOR(textToAlter, xord);

        assertArrayEquals(textToAlter, xor.multiByteXOR(alteredText, xord));
        assertArrayEquals(xord, xor.multiByteXOR(textToAlter, alteredText));
        System.arraycopy(alteredText, 0, cipherText, 32, alteredText.length);

        assertTrue(oracle.findAdminInCipherText(cipherText));
    }
}
