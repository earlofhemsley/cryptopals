package cryptopals.tool.sec06;

import cryptopals.tool.sec05.RSA;
import cryptopals.utils.MathUtil;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.util.Random;

/**
 * a class to abuse the RSA decryption oracle
 */
public class C41_RSAOracleAbuser {

    private final BigInteger E; // the RSA lock exponent
    private final BigInteger N; // the RSA lock modulus
    private final BigInteger S; // a random number coprime to N ... 1 < S < N

    public C41_RSAOracleAbuser(RSA.Key lock) {
        this.E = lock.getK();
        this.N = lock.getN();
        final Random r = new Random(System.currentTimeMillis());
        S = BigInteger.probablePrime(N.bitLength() / 100, r);
        if (S.compareTo(N) > 0) {
            throw new IllegalStateException("S > N");
        }
    }

    /**
     * take an actual cipher text and spawn a fake cipher text from it
     *
     * @param actualCipherText an actual cipherText "intercepted"
     * @return a modified cipher text to be submitted for decryption
     */
    public String spawnFakeRSACipherText(String actualCipherText) {
        final BigInteger C = new BigInteger(1, Base64.decodeBase64(actualCipherText));
        final BigInteger Cp = S.modPow(E, N).multiply(C).mod(N);
        return Base64.encodeBase64String(Cp.toByteArray());
    }

    /**
     * take a fake plain text and turn it into an actual plain text
     *
     * @param base64FakeDecryption a decryption from the oracle of a fake cipher text
     * @return the plain text
     */
    public String convertFakeDecryptionToActual(String base64FakeDecryption) {
        final byte[] debased = Base64.decodeBase64(base64FakeDecryption);
        final BigInteger Sp = MathUtil.invMod(S, N);
        final BigInteger Pp = new BigInteger(1, debased);
        final BigInteger P = Pp.multiply(Sp).mod(N);
        return new String(P.toByteArray());
    }
}
