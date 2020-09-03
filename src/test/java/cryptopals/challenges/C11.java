package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.ECB;
import cryptopals.tool.sec02.Challenge11Tool;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * An ECB/CBC detection oracle
 *
 * Now that you have ECB and CBC working:
 *
 * Write a function to generate a random AES key; that's just 16 random bytes.
 *
 * Write a function that encrypts data under an unknown key ---
 * that is, a function that generates a random key and encrypts under it.
 *
 * The function should look like:
 *
 * encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]
 *
 * Under the hood, have the function append 5-10 bytes (count chosen randomly)
 * before the plaintext and 5-10 bytes after the plaintext.
 *
 * Now, have the function choose to encrypt under ECB 1/2 the time,
 * and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
 *
 * Detect the block cipher mode the function is using each time.
 * You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC,
 * tells you which one is happening.
 */
public class C11 {
    @Test
    public void testChallenge11() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, DecoderException {
        String myHackerInput = "Acknowledgement Acknowledgement Acknowledgement Lorem Ipsum is simply dummy text of the printing and typesetting industry.";
        for(int i = 0; i<1000; i++) {
            var result = new Challenge11Tool().encryptionOracleUnknownMode(myHackerInput.getBytes());
            boolean ecbDetected = new ECB("1234567890123456".getBytes()).detectECBInCipherBytes(result.getRight());
            assertEquals(result.getLeft(), ecbDetected);
        }
    }
}
