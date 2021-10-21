package cryptopals.tool.sec05.c39;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import cryptopals.utils.MathUtil;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.tuple.Triple;

import java.math.BigInteger;
import java.util.Random;

@UtilityClass
public class RSA {

    public Triple<BigInteger, BigInteger, BigInteger> keyGen() {
        //pick two random primes
        final Random r = new Random(System.currentTimeMillis());
        final BigInteger p = BigInteger.probablePrime(2048, r);
        BigInteger q;
        do { q = BigInteger.probablePrime(2048, r); } while (p.compareTo(q) == 0);
        //get their product
        BigInteger n = p.multiply(q);
        //find the totient T
        BigInteger T = p.subtract(ONE).multiply(q.subtract(ONE));
        //find a prime that doesn't divide into the totient ... just start with 3 for now
        BigInteger e;
        do { e = BigInteger.probablePrime(8, r); } while (e.compareTo(T) > 0 || e.mod(T).compareTo(ZERO) == 0);
        //find the multiplicative inverse of this number mod T
        BigInteger d = MathUtil.invMod(e, T);
        //the key is e, d, n
        return Triple.of(e, d, n);
    }

    public String encrypt(String message, BigInteger e, BigInteger n) {return null;}

    public String decrypt(String cipherText, BigInteger e, BigInteger n) {return null;}
}