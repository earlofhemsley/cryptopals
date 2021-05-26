package cryptopals.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.IntStream;

/**
 * Pits the temper method of the MT19937_32 class
 * against the unTemper method of the MT19937_32_Splicer class
 *
 * verifies that a value can be recovered after being tempered
 */
public class MT19937_32TemperTests {

    private final MT19937_32 rng = new MT19937_32();
    private final MT19937_32_Splicer antiRng = new MT19937_32_Splicer();

    @ParameterizedTest
    @MethodSource("supplyInts")
    void temperAndUnTemper(final int untempered) {
        final int tempered = rng.temper(untempered);
        assertEquals(untempered, antiRng.unTemper(tempered));
    }

    static IntStream supplyInts() {
        return IntStream.range(-1000, 1001);
    }
}
