package cryptopals.utils;

import lombok.experimental.UtilityClass;

@UtilityClass
public class MathUtil {

    /**
     * find the modular inverse of e mod n, which we call d
     * an implementation of the extended euclidean algorithm
     * sourced from <a href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers" target="_blank">wikipedia</a>
     * @param e the number
     * @param n the modulus
     * @return the result, which I am calling d
     */
    public int invMod(final int e, final int n) {
        int d = 0;
        int nextD = 1;
        int r = n;
        int newr = e;

        while (newr != 0) {
            int q = r / newr;
            int tempD = d;
            d = nextD;
            nextD = tempD - q * nextD;

            int tempR = r;
            r = newr;
            newr = tempR - q * newr;
        }

        if (r > 1) {
            throw new ArithmeticException("a is not invertible");
        }

        if (d < 0) {
            d += n;
        }

        return d;
    }
}
