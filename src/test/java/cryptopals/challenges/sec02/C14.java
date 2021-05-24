package cryptopals.challenges.sec02;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import cryptopals.exceptions.ECBException;
import cryptopals.tool.sec02.Challenge14Tool;
import org.junit.jupiter.api.Test;

import java.util.Base64;

/**
 * Byte-at-a-time ECB decryption (Harder)
 * Take your oracle function from #12. Now generate a random count of random bytes
 * and prepend this string to every plaintext. You are now doing:
 *
 * AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
 * Same goal: decrypt the target-bytes.
 *
 * Stop and think for a second.
 * What's harder than challenge #12 about doing this? How would you overcome that obstacle?
 * The hint is: you're using all the tools you already have; no crazy math is required.
 *
 * Think "STIMULUS" and "RESPONSE".
 */
public class C14 {
    @Test
    public void testChallenge14() throws ECBException {
        String unknownInput = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK";

        byte[] unknownInputDecoded = Base64.getDecoder().decode(unknownInput.getBytes());
        byte[] decrypted = new Challenge14Tool().breakECBEncryptionWithPrefixUsingOracle(unknownInputDecoded);
        assertArrayEquals(unknownInputDecoded, decrypted);
    }
}
