package cryptopals.tool;

public class MT19937 {

    // word length
    private static final int W = 32;

    // degree of recurrence
    private static final int N = 624;

    // middle word, an offset used in the recurrence relation defining series x
    private static final int M = 397;

    // number of bits in LMASK (separation point of one word)
    private static final int R = 31;

    // a constant seemingly chosen at random
    private static final int F = 1812433253;

    //coefficients of the rational normal form twist matrix
    private static final int A = 0x9908B0DF;

    //shifting constants
    private static final int U = 29;
    private static final int S = 17;
    private static final int T = 37;
    private static final int L = 18;


    //masks
    private static final int LMASK = Integer.MAX_VALUE; //0x7fffffff
    private static final int UMASK = Integer.MIN_VALUE; //0x80000000
    private static final int D = 0xFFFFFFFF;
    private static final int B = 0x9D2C5680;
    private static final int C = 0xEFC60000;


    private int index = N;
    private final int[] MT = new int[N];

    public MT19937() {
        this((int) System.currentTimeMillis());
    }

    /**
     * the constructor seeds the state array
     * @param seed the integer seed value
     */
    public MT19937(final int seed) {
        MT[0] = seed;
        for (int i = 1; i < N; i++) {
            MT[i] = F * (MT[i-1] ^ (MT[i-1] >> (W-2))) + i;
        }
    }

    /**
     * extract_number ... gets the next number
     * @return the next psuedo-random int
     */
    public int nextInt() {
        if (index >= N) {
            twist();
            index = 0;
        }

        long y = MT[index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        return (int) y;
    }

    /**
     * re-populates the state array with a new set of random numbers
     * based on math that I once could understand but probably can't
     * anymore
     */
    private void twist() {
        for (int i = 0; i < N - 1; i++) {
            int xku = (MT[i] & UMASK);
            int xkl = (MT[i + 1] % N) & LMASK;
            int x = xku | xkl;
            int xA = x >> 1;
            if ((x & 1) != 0) {
                xA = xA ^ A;
            }
            MT[i] = MT[(i + M) % N] ^ xA;
        }
    }
}
