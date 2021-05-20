package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.MT19937_32;
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
        final MT19937_32 twister = new MT19937_32(seed);
        final MT19937_32 otherTwister = new MT19937_32(seed);

        for (int i = 0; i < 100000; i++) {
            assertEquals(twister.nextInt(), otherTwister.nextInt());
        }
    }

    @Test
    void testSameSequenceAsOriginal() {
        final int[] expected = new int[] {
                -795755684, 581869302, -404620562, -708632711, 545404204,
                -133711905, -372047867, 949333985, -1579004998, 1323567403
        };

        final MT19937_32 twister = new MT19937_32();

        for (int j : expected) {
            var next = twister.nextInt();
            assertEquals(j, next);
        }

    }

}
