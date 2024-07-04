package cryptopals.challenges.sec02;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import cryptopals.tool.sec02.Challenge14Tool;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.RepeatedTest;
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
@Slf4j
public class C14 {

    @RepeatedTest(100)
    public void testChallenge14() {
        String unknownInput = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK";

        byte[] unknownInputDecoded = Base64.getDecoder().decode(unknownInput.getBytes());
        log.debug("decoded input: {}", new String(unknownInputDecoded));
        byte[] extracted =  Challenge14Tool.extractTheMysteryString();
        assertArrayEquals(unknownInputDecoded, extracted);
    }
}
