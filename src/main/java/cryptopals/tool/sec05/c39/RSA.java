package cryptopals.tool.sec05.c39;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import cryptopals.utils.MathUtil;
import lombok.Data;
import lombok.experimental.UtilityClass;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.Random;

@UtilityClass
public class RSA {

    /**
     * generate an RSA key pair
     * @param bitLength the bit length of the desired key parameters
     * @return a pair of RSA keys
     */
    public Pair<Key, Key> keyGen(final int bitLength) {
        //pick two random primes not equal to each other
        final Random r = new Random(System.currentTimeMillis());
        final BigInteger p = BigInteger.probablePrime(bitLength, r);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(bitLength, r);
        } while (p.compareTo(q) == 0);

        //get their product
        BigInteger n = p.multiply(q);

        //find phi(n), which is the quantity of figures less than n that are coprime with n
        BigInteger phiN = p.subtract(ONE).multiply(q.subtract(ONE));

        //find a prime e that is coprime with phi(N)
        // phi(N) is not going to be prime since it's a product
        // the two numbers we multiplied together to get phiN also may not be prime since they are
        // prime numbers minus one
        // we will find an e coprime to phi(N) if we use a prime number less than phiN that doesn't divide phiN
        // we limit this value to 8 bits (max of 255) ...
        // its value is less important than it being coprime with phiN and less than phiN
        BigInteger e;
        do {
            e = BigInteger.probablePrime(8, r);
        } while (e.compareTo(phiN) > 0 || e.mod(phiN).compareTo(ZERO) == 0);

        //find the multiplicative inverse of this number mod phiN
        BigInteger d = MathUtil.invMod(e, phiN);
        //the key is [e, n] and [d, n]
        return Pair.of(new Key(e, n), new Key(d, n));
    }

    /**
     * encrypt a message given an RSA lock
     * @param message the message
     * @param publicLock the lock
     * @return the cipher text
     */
    public String encrypt(String message, Key publicLock) {
        //turn message into a number
        BigInteger m = new BigInteger(1, message.getBytes());

        //mod pow that number with the public key
        BigInteger c = m.modPow(publicLock.k, publicLock.n);

        //encode and return
        return Base64.encodeBase64String(c.toByteArray());
    }

    /**
     * decrypt a message given an RSA key
     * @param cipherText the cipherText
     * @param privateKey the key
     * @return the plain text
     */
    public String decrypt(String cipherText, Key privateKey) {
        //turn message back into a number
        BigInteger c = new BigInteger(1, Base64.decodeBase64(cipherText));

        //mod pow using the private key
        BigInteger m = c.modPow(privateKey.k, privateKey.n);

        //re-interpret that as a string and return
        return new String(m.toByteArray());
    }

    @Data
    public static class Key {
        private final BigInteger k;
        private final BigInteger n;
    }
}