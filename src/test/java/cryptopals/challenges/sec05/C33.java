package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertEquals;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Implement Diffie-Hellman
 * For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.
 *
 * Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
 *
 * Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mod 37 ---
 * A = (g**a) % p.
 *
 * Do the same for "b" and "B".
 *
 * "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 ---
 * s = (B**a) % p.
 *
 * Do the same with A**b, check that you come up with the same "s".
 *
 * To turn "s" into a key, you can just hash it to create 128 bits of key material
 * (or SHA256 it to create a key for encrypting and a key for a MAC).
 *
 * Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:
 *
 * p:
 * ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
 * e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
 * 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
 * 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
 * 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
 * c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
 * bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
 * fffffffffffff
 *
 * g: 2
 *
 * This is very easy to do in Python or Ruby or other high-level languages that auto-promote
 * fixnums to bignums, but it isn't "hard" anywhere.
 *
 * Note that you'll need to write your own modexp (this is blackboard math, don't freak out), because you'll blow
 * out your bignum library raising "a" to the 1024-bit-numberth power.
 * You can find modexp routines on Rosetta Code for most languages.
 */
@Slf4j
public class C33 {

    private static final BigInteger SMALL_G = BigInteger.valueOf(5);
    private static final BigInteger SMALL_P = BigInteger.valueOf(37);

    private static final BigInteger BIG_G = BigInteger.valueOf(2);
    private static final BigInteger BIG_P = new BigInteger(1, Hex.decode(
               "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                    "fffffffffffff"
    ));

    @ParameterizedTest
    @MethodSource("supplySecrets")
    void completeTheChallenge(final BigInteger a, final BigInteger b, final BigInteger g, final BigInteger p) {
        //secret supplied ... a
        //alice public
        final BigInteger A = g.modPow(a, p);

        //secret supplied ... b
        //bob public
        final BigInteger B = g.modPow(b, p);

        //shared, from alice
        final BigInteger s1 = B.modPow(a, p);
        //shared, from bob
        final BigInteger s2 = A.modPow(b, p);

        assertEquals(s1, s2);

        //turn s1 into a key
        final byte[] byteHash = new SHA256.Digest().digest(s1.toByteArray());
        final String hash = Hex.toHexString(byteHash);
        log.info("for shared secret {} the hash is {}", s1, hash);
    }

    static Stream<Arguments> supplySecrets() {
        //start with the smaller numbers
        List<Arguments> arg = new ArrayList<>();
        for (int i = 0; i < SMALL_P.intValue(); i++) {
            for (int j = 0; j < SMALL_P.intValue(); j++) {
                arg.add(Arguments.arguments(BigInteger.valueOf(i), BigInteger.valueOf(j),
                        SMALL_G, SMALL_P));
            }
        }

        //now for the bigger numbers
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 100; j++) {
                arg.add(Arguments.arguments(BigInteger.valueOf(i), BigInteger.valueOf(j),
                        BIG_G, BIG_P));
            }
        }
        return arg.stream();
    }
}
