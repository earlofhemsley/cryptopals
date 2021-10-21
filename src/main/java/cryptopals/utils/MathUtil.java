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
     * @param e the number
     * @param n the modulus
     * @return the result, which I am calling d
     */
    public BigInteger invMod(final BigInteger e, final BigInteger n) {
        BigInteger d = BigInteger.ZERO;
        BigInteger nextD = BigInteger.ONE;
        BigInteger r = n;
        BigInteger nextR = e;

        while (nextR.compareTo(BigInteger.ZERO) != 0) {
            var q = r.divide(nextR);
            var tempD = d;
            d = nextD;
            nextD = tempD.subtract(q.multiply(nextD));

            var tempR = r;
            r = nextR;
            nextR = tempR.subtract(q.multiply(nextR));
        }

        if (r.compareTo(BigInteger.ONE) > 0) {
            throw new ArithmeticException("e is not invertible");
        }

        if (d.compareTo(BigInteger.ZERO) < 0) {
            d = d.add(n);
        }

        return d;
    }
}
