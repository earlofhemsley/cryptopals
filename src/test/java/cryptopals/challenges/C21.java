package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.MT19937;
import org.junit.jupiter.api.Test;

/**
 * Implement the MT19937 Mersenne Twister RNG
 * You can get the psuedocode for this from <a href="https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode">Wikipedia</a>.
 * If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
 */
public class C21 {

    /**
     * given an identical seed
     * the mersenne twister RNG should produce the same sequence of random numbers
     */
    @Test
    void testSameSeedSameSequence() {
        final int seed = 1776;
        final MT19937 twister = new MT19937(seed);
        final MT19937 otherTwister = new MT19937(seed);

        for (int i = 0; i < 100000; i++) {
            assertEquals(twister.nextInt(), otherTwister.nextInt());
        }
    }

}
