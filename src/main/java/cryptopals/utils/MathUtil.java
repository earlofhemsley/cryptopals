package cryptopals.utils;

import static com.google.common.base.Preconditions.checkArgument;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import com.google.common.base.Preconditions;
import lombok.experimental.UtilityClass;

import java.math.BigInteger;

@UtilityClass
public class MathUtil {
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * find the modular inverse of a mod n, which we call t
     * an implementation of the extended euclidean algorithm
     * sourced from <a href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers" target="_blank">wikipedia</a>
     *
     * this is functionally equivalent to {@link BigInteger#modInverse(BigInteger)}
     *
     * @param a the number
     * @param n the modulus
     * @return the result, which I am calling t
     */
    public BigInteger invMod(final BigInteger a, final BigInteger n) {
        checkArgument(!n.mod(a).equals(ZERO), "n mod a cannot equal zero");

        BigInteger t = BigInteger.ZERO;
        BigInteger nextT = ONE;
        BigInteger r = n;
        BigInteger nextR = a;

        while (nextR.compareTo(BigInteger.ZERO) != 0) {
            var q = r.divide(nextR);
            var tempT = t;
            t = nextT;
            nextT = tempT.subtract(q.multiply(nextT));

            var tempR = r;
            r = nextR;
            nextR = tempR.subtract(q.multiply(nextR));
        }

        if (r.compareTo(ONE) > 0) {
            throw new ArithmeticException(String.format("%s not invertible. n mod a = %s", a, n.mod(a)));
        }

        if (t.compareTo(BigInteger.ZERO) < 0) {
            t = t.add(n);
        }

        return t;
    }

    public BigInteger iroot(int k, int n) {
        return iroot(BigInteger.valueOf(k), BigInteger.valueOf(n));
    }

    /**
     * find the kth root of figure n
     * @param k the root
     * @param n the figure
     * @return the kth root of figure n
     */
    public BigInteger iroot(final BigInteger k, final BigInteger n) {
        //initial guess
        final var k1 = k.subtract(ONE);
        var s = n.add(ONE);
        var u = n;
        while (u.compareTo(s) < 0) {
            s = u;
            u = u.multiply(k1).add(n.divide(u.pow(k1.intValue()))).divide(k);
        }
        return s;
    }
}
