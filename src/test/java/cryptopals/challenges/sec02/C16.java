package cryptopals.challenges.sec02;

import static cryptopals.tool.sec02.Challenge16Oracle.firstFunction;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.XOR;
import cryptopals.tool.sec02.Challenge16Oracle;
import cryptopals.utils.ByteArrayUtil;
import org.junit.jupiter.api.Test;

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
    public void simpleInjectionDoesNotWork() {
        //the direct injection attack should not work.
        // "if you've written the first function properly it should be possible to provide user input
        // to it that will generate the string the second function is looking for"

        final var hackerInput = "yey;admin=true"; //this would be a typical injection attack
        final var enc = firstFunction(hackerInput);
        assertFalse(Challenge16Oracle.secondFunction(enc));
    }

    @Test
    public void testChallenge16() throws Exception {
        //0123456789012345|0123456789012345|0123456789012345|0123456789012345|0123456789...
        //comment1=cooking|%20MCs;userdata=|AAAAAAAAAAAAAAAA|SadminEtrueSAEAA|;comment2=...

        //                                  ^^^^^^^^^^^^^^^^
        // if we edit this block, or apply an edit to it, the edits will roll into the following block
        // and allow us to edit input we know won't be sanitized

        //TODO: split this off into a tool?
        String knownInput = "SadminEtrueSaEaa"; // S for semicolon, E for equals
        String desired = ";admin=true;a=aa";
        assertEquals(16, knownInput.length());
        assertEquals(16, desired.length());

        byte[] xorResult = XOR.multiByteXOR(knownInput.getBytes(), desired.getBytes());
        assertArrayEquals(desired.getBytes(), XOR.multiByteXOR(knownInput.getBytes(), xorResult));
        assertArrayEquals(knownInput.getBytes(), XOR.multiByteXOR(desired.getBytes(), xorResult));

        //prepend with a block that we don't care if it gets scrambled
        final var hackerInput = "AAAAAAAAAAAAAAAA" + knownInput;
        final var encrypted = Challenge16Oracle.firstFunction(hackerInput);

        // apply the bitflipping attack by finding the first block that is changed when we modify the input
        // this is the start of the block that we will want to edit
        final var secondHackerInput = "BAAAAAAAAAAAAAAA" + knownInput;
        final var encrypted2 = Challenge16Oracle.firstFunction(secondHackerInput);
        assertEquals(encrypted.length, encrypted2.length);

        int idx = 0;
        while (encrypted2[idx] == encrypted[idx]) {
            idx++;
        }
        assertNotEquals(0, idx);
        assertNotEquals(encrypted.length, idx);

        var abusableBlock = ByteArrayUtil.sliceByteArray(encrypted, idx, xorResult.length);
        var withEditApplied = XOR.multiByteXOR(abusableBlock, xorResult);
        System.arraycopy(withEditApplied, 0, encrypted, idx, withEditApplied.length);

        assertTrue(Challenge16Oracle.secondFunction(encrypted));
    }
}
