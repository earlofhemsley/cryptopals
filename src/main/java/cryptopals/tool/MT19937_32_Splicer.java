package cryptopals.tool;

import static com.google.common.base.Preconditions.checkArgument;
import static cryptopals.utils.BitMaskUtil.convertIntToLeftEndMask;
import static cryptopals.utils.BitMaskUtil.convertIntToRightEndMask;

import cryptopals.exceptions.CryptopalsException;

import java.lang.reflect.Field;

/**
 * Class dedicated to deriving the internal state of a mersenne twister
 * rng and returning a clone of the original object without knowing the seed
 * this is intended to be the anti-mersenne twister - a class that can build
 * a mersenne twister without knowing the seed
 */
public class MT19937_32_Splicer {
    // these fields are defined in the MT19937 spec.
    private static final int W = 32;
    private static final int N = 624;
    private static final int FULL_MASK = 0xFFFFFFFF;
    private static final int U = 11;
    private static final int S = 7;
    private static final int T = 15;
    private static final int L = 18;
    private static final int D = 0xFFFFFFFF;
    private static final int B = 0x9D2C5680;
    private static final int C = 0xEFC60000;

    public MT19937_32 splice(final int[] samples) {
        checkArgument(samples.length >= N, String.format("Cannot accept fewer than %d samples", N));
        final int[] untempered = new int[N];
        for (int i = 0; i < untempered.length; i++) {
            untempered[i] = unTemper(samples[i]);
        }

        final MT19937_32 clone = new MT19937_32();
        Field mt;
        try {
            mt = clone.getClass().getDeclaredField("MT");
            mt.setAccessible(true);
            mt.set(clone, untempered);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new CryptopalsException("Could not create a clone", e);
        }

        return clone;
    }

    int unTemper(final int tempered) {
        int y = unTemperRightShift(tempered, L, FULL_MASK);
        y = unTemperLeftShift(y, T, C);
        y = unTemperLeftShift(y, S, B);
        y = unTemperRightShift(y, U, D);
        return y;
    }

    private int unTemperRightShift(final int z, final int shift, final int maskConst) {
        final int blockMask = convertIntToLeftEndMask(shift);
        int zp = z;
        for (int blockMaskShift = 0; blockMaskShift < (W - shift); blockMaskShift += shift) {
            zp = zp ^ (((zp & (blockMask >>> blockMaskShift)) >>> shift) & maskConst);
        }
        return zp;
    }

    private int unTemperLeftShift(final int z, final int shift, final int maskConst) {
        final int blockMask = convertIntToRightEndMask(shift);
        int zp = z;
        for (int blockMaskShift = 0; blockMaskShift < (W - shift); blockMaskShift += shift) {
            zp = zp ^ (((zp & (blockMask << blockMaskShift)) << shift) & maskConst);
        }
        return zp;
    }
}
