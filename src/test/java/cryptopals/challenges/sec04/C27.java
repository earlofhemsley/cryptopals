package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import cryptopals.exceptions.InvalidPlaintextByteException;
import cryptopals.tool.XOR;
import cryptopals.tool.sec04.C27_SameKeyIVAdminRightsOracle;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

/**
 * Recover the key from CBC with IV=Key
 *
 * Take your code <a href="https://cryptopals.com/sets/2/challenges/16">from the CBC exercise</a> and modify it
 * so that it repurposes the key for CBC encryption as the IV.
 *
 * Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know
 * the key already, and can save some space by using it as both a key and an IV.
 *
 * Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get
 * the receiver to decrypt a value that will reveal the key.
 *
 * The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance
 * (ie, look for high-ASCII values). Non-compliant messages should raise an exception or return an error that
 * includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).
 *
 * Use your code to encrypt a message that is at least 3 blocks long:
 * AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
 *
 * Modify the message (you are now the attacker):
 * C_1, C_2, C_3 -> C_1, 0, C_1
 *
 * Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
 *
 * As the attacker, recovering the plaintext from the error, extract the key:
 * P'_1 XOR P'_3
 *
 * */
@Slf4j
public class C27 {

    private static final int BLOCK_LENGTH = 16;

    private static final byte[] KEY = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private final C27_SameKeyIVAdminRightsOracle oracle = new C27_SameKeyIVAdminRightsOracle(KEY);

    /**
     *
     */
    @Test
    void doTheChallenge() {
        //encrypt a message
        final String msg = "This bad message";
        var enc = oracle.padAndEncrypt(msg);

        //alter the message
        var c1 = ByteArrayUtil.sliceByteArray(enc, 0, BLOCK_LENGTH);
        System.arraycopy(new byte[BLOCK_LENGTH], 0, enc, BLOCK_LENGTH, BLOCK_LENGTH);
        System.arraycopy(c1, 0, enc, BLOCK_LENGTH*2, c1.length);

        //catch the exception
        try {
            oracle.findAdminInCipherText(enc);
        } catch (InvalidPlaintextByteException ex) {
            final byte[] pp = ex.getPlainTextBytes();
            final byte[] pp1 = ByteArrayUtil.sliceByteArray(pp, 0, BLOCK_LENGTH);
            final byte[] pp3 = ByteArrayUtil.sliceByteArray(pp, BLOCK_LENGTH*2, BLOCK_LENGTH);
            //this should yield the key
            final byte[] derivedKey = new XOR().multiByteXOR(pp1, pp3);
            assertArrayEquals(KEY, derivedKey);
        }
    }
}
