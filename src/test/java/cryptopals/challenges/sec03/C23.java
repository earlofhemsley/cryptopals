package cryptopals.challenges.sec03;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.MT19937_32;
import cryptopals.tool.MT19937_32_Splicer;
import org.junit.jupiter.api.Test;

/**
 * Clone an MT19937 RNG from its output
 * The internal state of MT19937 consists of 624 32 bit integers.
 *
 * For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a
 * period of 2**19937, which is Big.
 *
 * Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses
 * bits through the result.
 *
 * The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and
 * transforms it back into the corresponding element of the MT19937 state array.
 *
 * To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order.
 * There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted
 * value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert
 * the "right" and the "left" operation.
 *
 * Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to
 * recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.
 *
 * The new "spliced" generator should predict the values of the original.
 */
public class C23 {

    //this value comes from the test requirement and the MT spec
    private static final int N = 624;

    @Test
    void challenge23() {

        final var original = new MT19937_32(1776);
        final int[] samples = new int[N];
        for (int i = 0; i < samples.length; i++) {
            samples[i] = original.nextInt();
        }

        final var clone = new MT19937_32_Splicer().splice(samples);

        //verify that the clone returns the same next million values as the original
        for (int i = 0; i < 1000000; i++) {
            assertEquals(clone.nextInt(), original.nextInt());
        }
    }

}
