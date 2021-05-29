package cryptopals.challenges.sec03;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.MT19937_32;
import cryptopals.tool.PRNG_CTR;
import cryptopals.tool.sec03.C24_PrngCtrBreaker;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Create the MT19937 stream cipher and break it
 * You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call
 * those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.
 *
 * Write the function that does this for MT19937 using a 16-bit seed.
 * Verify that you can encrypt and decrypt properly.
 * This code should look similar to your CTR code.
 *
 * Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters)
 * prefixed by a random number of random characters.
 *
 * From the ciphertext, recover the "key" (the 16 bit seed).
 *
 * Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
 *
 * Write a function to check if any given password token is actually the product of an MT19937 PRNG
 * seeded with the current time.
 */
@Slf4j
public class C24 {

    @Test
    void testReversibility() {
        final var tool = new PRNG_CTR((short) 1776);
        final var sample = "GIVE ME LIBERTY, OR GIVE ME DEATH";

        final var encrypted = tool.encrypt(sample);
        assertEquals(sample, tool.decrypt(encrypted));
    }

    @ParameterizedTest
    @ValueSource(ints = {1,2,3,4,5,6,7,8,9,10})
    void recoverTheKeyGivenKnownPlainText(final int time) {
        log.info("starting attempt {}", time);
        final var rando = new MT19937_32((short) System.currentTimeMillis());
        final var numOfRandomCharacters = rando.nextIntBetween(10, 31);
        final String knownPlainText = "AAAAAAAAAAAAAA";
        final var sb = new StringBuilder();
        for (int i = 0; i < numOfRandomCharacters; i++) {
           sb.append((char) rando.nextIntBetween('a', 'z'));
        }
        sb.append(knownPlainText);
        final var plainText = sb.toString();
        final short key = (short) rando.nextInt();
        log.info("The plaintext is {} and the key is {}", plainText, key);

        var prngCtr = new PRNG_CTR(key);
        var encrypted = prngCtr.encrypt(plainText);
        final C24_PrngCtrBreaker breaker = new C24_PrngCtrBreaker();

        assertEquals(key, breaker.bruteForcePRNGCTRKey(encrypted, knownPlainText));
        log.info("attempt {} successful", time);
    }
}
