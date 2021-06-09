package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import cryptopals.exceptions.InvalidPlaintextByteException;
import cryptopals.tool.XOR;
import cryptopals.tool.sec04.C27_SameKeyIVAdminRightsOracle;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.regex.Pattern;

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

    private static final byte[] KEY = ByteArrayUtil.randomBytes(16);
    private final C27_SameKeyIVAdminRightsOracle oracle = new C27_SameKeyIVAdminRightsOracle(KEY);

    @Test
    void ensureUntamperedMessageWorks() {
        final String msg = ";admin=true;A=AA";
        var enc = oracle.padAndEncrypt(msg);
        assertFalse(oracle.findAdminInCipherText(enc));
    }

    /**
     * complete the challenge
     *
     * this specifically takes advantage of the decryption algorithm.
     *
     * in order to recover the key, (since the key and the iv are the same), you need to XOR an
     * encrypted first block against a plaintext first block
     *
     * getting the plaintext first block is easy. decrypt normally.
     * getting the encrypted first block is less obvious. to get the encrypted first block, you
     * need to take advantage of the cbc algorithm.
     *
     * cbc, when decrypting, will take an encrypted block and xor it against the next block after that next
     * block has been ecb decrypted to reveal the plaintext.
     *
     * so, if you overwrite the second block of ciphertext with all zeros and overwrite the third block of
     * ciphertext with the first block of ciphertext, the algorithm will ecb decrypt that third block (which is really
     * the first block) and then xor it against all 0s, which leaves that ecb decrypted third block unaltered
     * (since an xor against 0 does nothing). And voila! You've got your two components: the ecb decrypted first
     * block, and your plaintext first block.
     *
     * When you xor these two, you get the IV, which in this challenge, is also the key.
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
            final Pattern p = Pattern.compile("^\\[([\\d, -]+)] contains an invalid character: [\\d-]+$");
            var m = p.matcher(ex.getMessage());
            if (m.find()) {
                var splits = m.group(1).split(", ");

                //pp = p prime, or plaintaxt prime
                var pp = ArrayUtils.toPrimitive(Arrays.stream(splits).map(Byte::parseByte).toArray(Byte[]::new));

                //block one (plaintext fully decrypted)
                final byte[] pp1 = ByteArrayUtil.sliceByteArray(pp, 0, BLOCK_LENGTH);

                //block three (ciphertext block one ecb decrypted and xor'd against 0)
                final byte[] pp3 = ByteArrayUtil.sliceByteArray(pp, BLOCK_LENGTH*2, BLOCK_LENGTH);

                //xor the two to get the key
                final byte[] derivedKey = new XOR().multiByteXOR(pp1, pp3);
                assertArrayEquals(KEY, derivedKey);
            } else {
                fail("couldn't find the byte array plaintext");
            }
        }
    }
}
