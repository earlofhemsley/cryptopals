package cryptopals.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import java.math.BigInteger;

public class MathUtilTests {

    /**
     * this tests parity between java's BigInteger modInverse method
     * and my homebrewed modInv method based on the extended euclidian
     * algorithm
     * @param prime a prime number between 0 and 100k, sourced from a file
     */
    @ParameterizedTest
    @CsvFileSource(files = "src/test/resources/primes-to-100k.txt")
    void invModTest(String prime) {
        final BigInteger n = BigInteger.valueOf(100003);

        final BigInteger e = new BigInteger(prime);

        assertEquals(e.modInverse(n), MathUtil.invMod(e, n));
    }
}
