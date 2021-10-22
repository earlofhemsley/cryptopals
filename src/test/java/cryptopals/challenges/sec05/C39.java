package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.sec05.c39.RSA;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;

/**
 * Implement RSA
 * There are two annoying things about implementing RSA. Both of them involve key generation;
 * the actual encryption/decryption in RSA is trivial.
 *
 * First, you need to generate random primes. You can't just agree on a prime ahead of time, like you do in DH.
 * You can write this algorithm yourself, but I just cheat and use OpenSSL's BN library to do the work.
 *
 * The second is that you need an "invmod" operation (the multiplicative inverse), which is not an operation that
 * is wired into your language. The algorithm is just a couple lines, but I always lose an hour getting it to work.
 *
 * I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.
 *
 * Now:
 *
 * Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table.
 * Call them "p" and "q".
 * Let n be p * q. Your RSA math is modulo n.
 * Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
 * Let e be 3.
 * Compute d = invmod(e, et). invmod(17, 3120) is 2753.
 * Your public key is [e, n]. Your private key is [d, n].
 * To encrypt: c = m**e%n. To decrypt: m = c**d%n
 * Test this out with a number, like "42".
 * Repeat with bignum primes (keep e=3).
 *
 * Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it
 * to turn it into a number. The math cares not how stupidly you feed it strings.
 */
@Slf4j
public class C39 {

    @RepeatedTest(1000)
    void keyGenWorks() {
        final var key = RSA.keyGen(8);
        final RSA.Key publicKey = key.getLeft();
        final RSA.Key privateKey = key.getRight();
        BigInteger fortyTwo = BigInteger.valueOf(42);
        assertEquals(fortyTwo, fortyTwo.modPow(publicKey.getK(), publicKey.getN())
                .modPow(privateKey.getK(), privateKey.getN()));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "those who have not been enclosed in the walls of prison without cause or provocation, " +
                    "can have but little idea how sweet the voice of a friend is",
            "Truth is truth! It is not divisible, and any part of it cannot be set aside."
    })
    void encryptAndDecrypt(final String message) {
        log.info("original message: {}", message);
        final Pair<RSA.Key, RSA.Key> keyPair = RSA.keyGen(2048);
        final String cipherText = RSA.encrypt(message, keyPair.getLeft());
        log.info("cipher text: {}", cipherText);
        final String plainText = RSA.decrypt(cipherText, keyPair.getRight());
        log.info("plain text: {}", plainText);
        assertEquals(message, plainText);
    }

}
