package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.MT19937_32;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.IntStream;

/**
 * Crack an MT19937 seed
 * Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).
 *
 * Write a routine that performs the following operation:
 *
 * Wait a random number of seconds between, I don't know, 40 and 1000.
 * Seeds the RNG with the current Unix timestamp
 * Waits a random number of seconds again.
 * Returns the first 32 bit output of the RNG.
 * You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
 *
 * From the 32 bit RNG output, discover the seed.
 */
@Slf4j
public class C22 {

    /**
     * I think the idea of this is to iteratively troll through the passage of time, testing fewer than a thousand
     * candidate seeds in order to try to replicate the outputs of the RNG. Because it's deterministic, if you can
     * replicate the output, then you've cracked the seed
     *
     * ima simulate the passage of time, because I ain't got time for that
     */
    @ParameterizedTest
    @MethodSource("supply")
    void challenge22TenTimes(int time) {
        log.info("attempt {}", time);

        //simulate passage of time ... by writing a comment
        // ... time has passed
        final var rngOutput = getRngToBeCracked().nextInt();

        //since we don't know exactly when the seed was spawned, but we know it was time-based
        // get now + 1 million millis (the upper bound) and iteratively go back through
        // the previous 1.5 million milliseconds to find the seed
        // 1.5 to buffer it by 500000 milliseconds
        final long now = System.currentTimeMillis() + 1000000L;
        for (long i = 0; i < 1500000L; i++) {
            final long candidateSeed = now - i;
            final var newRNG = new MT19937_32(candidateSeed);
            if (newRNG.nextInt() == rngOutput) {
                log.info("Found it. The seed was {}", candidateSeed);
                return;
            }
        }
        Assertions.fail("Could not find the seed");
    }

    private MT19937_32 getRngToBeCracked() {
        //get now
        final long now = System.currentTimeMillis();

        //add a random number of seconds between 40 and 1000
        // try to make it more random by using a fresh rng and seeding it with the system time
        final int lower = 40 * 1000;
        final int upper = 1000 * 1000;
        final int millis = new MT19937_32(System.currentTimeMillis()).nextIntBetween(lower, upper);
        assertTrue(millis >= lower, "Millis was less than lower. Value: " + millis);
        assertTrue(millis < upper, "Millis was greater than upper. Value: " + millis);
        final long seed = now + millis;

        //seed a new RNG with this value
        return new MT19937_32(seed);
    }


    static IntStream supply() {
        return IntStream.range(1, 11);
    }


    /**
     * this is an auxiliary test for the prng's new nextIntBetweenMethod
     * it ensures that, over a million values, that the result is gte lower and lt upper
     * if the difference between lower and upper is 1, then the result should always always be lower
     */
    @Test
    void testNextIntBetween() {
        final var rng = new MT19937_32();
        for (int i = 0; i < 1000000; i++) {
            assertEquals(3, rng.nextIntBetween(3, 4));
        }
    }

}
