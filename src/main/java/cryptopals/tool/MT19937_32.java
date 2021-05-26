package cryptopals.tool;

import static cryptopals.utils.BitMaskUtil.convertIntToLeftEndMask;
import static cryptopals.utils.BitMaskUtil.convertIntToRightEndMask;

import com.google.common.base.Preconditions;

/**
 * an implementation of the mersenne twister prng for a 32-bit integer
 */
public class MT19937_32 {

    // word length
    private static final int W = 32;

    // degree of recurrence
    private static final int N = 624;

    // middle word, an offset used in the recurrence relation defining series x
    private static final int M = 397;

    // a constant seemingly chosen at random
    private static final int F = 1812433253;

    //coefficients of the rational normal form twist matrix
    private static final int A = 0x9908B0DF;

    //shifting constants
    private static final int U = 11;
    private static final int S = 7;
    private static final int T = 15;
    private static final int L = 18;

    //masks defined in the spec document
    private static final int LMASK = Integer.MAX_VALUE; //0x7fffffff
    private static final int UMASK = Integer.MIN_VALUE; //0x80000000
    private static final int D = 0xFFFFFFFF;
    private static final int B = 0x9D2C5680;
    private static final int C = 0xEFC60000;


    private int index = N;
    private final int[] MT = new int[N];
    private final Temper temper = new Temper();

    public MT19937_32() {
        this(5489);
    }

    /**
     * the constructor seeds the state array
     * @param seed the integer seed value
     */
    public MT19937_32(final int seed) {
        MT[0] = seed;
        for (int i = 1; i < N; i++) {
            MT[i] = F * (MT[i-1] ^ (MT[i-1] >>> (W-2))) + i;
        }
    }

    /**
     * overload the main constructor to take a long
     * @param seed long value
     */
    public MT19937_32(final long seed) {
        this((int) seed);
    }

    /**
     * extract_number ... gets the next number
     * @return the next psuedo-random int
     */
    public int nextInt() {
        if (index >= N) {
            twist();
        }

        //fetch the next number from the array
        // and do some "tempering" before returning
        int y = MT[index++];
        y = temper.first(y);
        y = temper.second(y);
        y = temper.third(y);
        y = temper.fourth(y);
        return y;
    }

    /**
     * get the next random number within a range of values
     * @param lowerBound the lower bound (inclusive). must be positive
     * @param upperBound the upper bound (exclusive). must be greater than lower bound
     * @return next pseudorandom value between the bounds
     */
    public int nextIntBetween(final int lowerBound, final int upperBound) {
        Preconditions.checkArgument(lowerBound < upperBound, "lower bound must be less than upper bound");

        final int range = upperBound - lowerBound;
        final int unShiftedResult = Math.abs(nextInt()) % range;
        return unShiftedResult + lowerBound;
    }

    /**
     * re-populates the state array with a new set of random numbers
     */
    private void twist() {
        for (int i = 0; i < N; i++) {
            //index in second half is i + 1 % N to protect against out of bounds
            int x = (MT[i] & UMASK) | ((MT[(i + 1) % N]) & LMASK);

            //the second half is only something if the lsb of x is 1
            // because an xor against 0 is the same as doing nothing
            int xA = (x >>> 1) ^ ((x & 1) * A);

            //index is, again, 1+M mod N to protect against out of bounds
            MT[i] = MT[(i + M) % N] ^ xA;
        }
        index = 0;
    }

    /**
     * a class for tempering AND un-tempering integers
     * according to the MT19337 32-bit specification
     */
    public static class Temper {
        //a full mask
        private static final int FULL_MASK = 0xFFFFFFFF;

        public int first(final int y) {
            return temperRightShift(y, U, D);
        }

        public int undoFirst(final int z) {
            return unTemperRightShift(z, U, D);
        }

        public int second(final int y) {
            return temperLeftShift(y, S, B);
        }

        public int undoSecond(final int z) {
            return unTemperLeftShift(z, S, B);
        }

        public int third(final int y) {
            return temperLeftShift(y, T, C);
        }

        public int undoThird(final int z) {
            return unTemperLeftShift(z, T, C);
        }

        public int fourth(final int y) {
            return temperRightShift(y, L, FULL_MASK);
        }

        public int undoFourth(final int z) {
            return unTemperRightShift(z, L, FULL_MASK);
        }

        private int temperRightShift(final int y, final int shift, final int mask) {
            return y ^ ((y >>> shift) & mask);
        }

        private int unTemperRightShift(final int z, final int shift, final int maskConst) {
            final int blockMask = convertIntToLeftEndMask(shift);
            int zp = z;
            for (int blockMaskShift = 0; blockMaskShift < (W - shift); blockMaskShift += shift) {
                zp = zp ^ (((zp & (blockMask >>> blockMaskShift)) >>> shift) & maskConst);
            }
            return zp;
        }

        private int temperLeftShift(final int y, final int shift, final int mask) {
            return y ^ ((y << shift) & mask);
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
}
