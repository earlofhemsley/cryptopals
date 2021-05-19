package cryptopals.challenges;

import cryptopals.tool.MT19937;
import org.junit.jupiter.api.Test;

/**
 * Implement the MT19937 Mersenne Twister RNG
 * You can get the psuedocode for this from <a href="https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode">Wikipedia</a>.
 * If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
 */
public class C21 {

    @Test
    void testTheTwister() {
        final MT19937 twister = new MT19937(1);
        twister.nextInt();
    }

}
