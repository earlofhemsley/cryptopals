package cryptopals.tool;

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

    //masks
    private static final int LMASK = Integer.MAX_VALUE; //0x7fffffff
    private static final int UMASK = Integer.MIN_VALUE; //0x80000000
    private static final int D = 0xFFFFFFFF;
    private static final int B = 0x9D2C5680;
    private static final int C = 0xEFC60000;


    private int index = N;
    private final int[] MT = new int[N];

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
        y = y ^ ((y >>> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >>> L);

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
}
