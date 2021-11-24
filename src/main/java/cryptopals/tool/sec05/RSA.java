package cryptopals.tool.sec05;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import cryptopals.utils.MathUtil;
import lombok.Data;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.Random;

/**
 * an implementation of RSA
 */
@Slf4j
@UtilityClass
public class RSA {

    public Pair<Key, Key> keyGen(final int bitLength) {
        return keyGen(bitLength, null);
    }

    /**
     * generate an RSA key pair
     * @param bitLength the bit length of the desired key parameters
     * @return a pair of RSA keys
     */
    public Pair<Key, Key> keyGen(final int bitLength, final Integer forceE) {
        final Random r = new Random(System.currentTimeMillis());

        //start with e. Pick an e
        final BigInteger e = forceE != null ? BigInteger.valueOf(forceE) :
                BigInteger.probablePrime(Math.min(32, bitLength), r);

        BigInteger n;
        BigInteger phiN;
        do {
            //pick two random primes not equal to each other
            final BigInteger p = BigInteger.probablePrime(bitLength, r);
            BigInteger q;
            do {
                q = BigInteger.probablePrime(bitLength, r);
            } while (p.compareTo(q) == 0);

            //get their product
             n = p.multiply(q);

            //find phi(n), which is the quantity of figures less than n that are coprime with n
            phiN = p.subtract(ONE).multiply(q.subtract(ONE));
        } while (e.compareTo(phiN) > 0 || phiN.mod(e).equals(ZERO));

        //find the multiplicative inverse of e mod phiN
        final BigInteger d = MathUtil.invMod(e, phiN);
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
     * decrypt a message to a string given an RSA key
     * @param cipherText the cipherText
     * @param privateKey the key
     * @return the plain text
     */
    public String decrypt(String cipherText, Key privateKey) {
        //re-interpret that as a string and return
        return new String(decryptToBytes(cipherText, privateKey));
    }

    /**
     * decrypt a message to a byte array given an RSA key
     * @param cipherText the cipher text
     * @param privateKey the key
     * @return the decrypted byte array
     */
    public byte[] decryptToBytes(String cipherText, Key privateKey) {
        //turn message back into a number
        BigInteger c = new BigInteger(1, Base64.decodeBase64(cipherText));

        //mod pow using the private key
        BigInteger m = c.modPow(privateKey.k, privateKey.n);

        return m.toByteArray();
    }

    @Data
    public static class Key {
        private final BigInteger k;
        private final BigInteger n;
    }
}