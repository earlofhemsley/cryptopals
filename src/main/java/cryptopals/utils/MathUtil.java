package cryptopals.utils;

import lombok.experimental.UtilityClass;
import org.bouncycastle.pqc.math.linearalgebra.BigEndianConversions;

import java.math.BigInteger;

@UtilityClass
public class MathUtil {

    /**
     * find the modular inverse of e mod n, which we call d
     * an implementation of the extended euclidean algorithm
     * sourced from <a href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers" target="_blank">wikipedia</a>
     * @param a the number
     * @param n the modulus
     * @return the result, which I am calling t
     */
    public BigInteger invMod(final BigInteger a, final BigInteger n) {
        BigInteger t = BigInteger.ZERO;
        BigInteger nextT = BigInteger.ONE;
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

        if (r.compareTo(BigInteger.ONE) > 0) {
            throw new ArithmeticException("e is not invertible");
        }

        if (t.compareTo(BigInteger.ZERO) < 0) {
            t = t.add(n);
        }

        return t;
    }
}
