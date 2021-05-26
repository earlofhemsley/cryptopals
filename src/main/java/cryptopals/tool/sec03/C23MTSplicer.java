package cryptopals.tool.sec03;

import static cryptopals.tool.MT19937_32.Temper;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.MT19937_32;

import java.lang.reflect.Field;

/**
 * Class dedicated to deriving the internal state of a mersenne twister
 * rng and returning a clone of the original object without knowing the seed
 */
public class C23MTSplicer {
    /**
     * defined in the MT spec
     */
    private static final int N = 647;

    public MT19937_32 cloneTheTwister(final MT19937_32 original) throws NoSuchFieldException, IllegalAccessException {
        final int[] samples = new int[N];
        final int[] untempered = new int[N];
        for (int i = 0; i < untempered.length; i++) {
            samples[i] = original.nextInt();
            untempered[i] = unTemper(samples[i]);
        }

        final MT19937_32 clone = new MT19937_32();
        Field mt = original.getClass().getDeclaredField("MT");
        mt.setAccessible(true);
        mt.set(clone, untempered);

        // verify that the clone returns the same sample array that we extracted from the original
        for (int i = 0; i < N; i++) {
            final int next = clone.nextInt();
            if (samples[i] != next) {
                throw new CryptopalsException(String.format("Unable to replicate behavior for the nth figure. n = %d, %d != %d",
                        i, samples[i], next));
            }
        }

        return clone;
    }

    private int unTemper(final int tempered) {
        final Temper ut = new Temper();
        int y = ut.undoFourth(tempered);
        y = ut.undoThird(y);
        y = ut.undoSecond(y);
        y = ut.undoFirst(y);
        return y;
    }
}
