package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.CTR;
import cryptopals.tool.ECB;
import cryptopals.tool.XOR;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.FileUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Base64;

/**
 * Break "random access read/write" AES CTR
 * Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key
 * (for this exercise the key should be unknown to you, but hold on to it).
 *
 * Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext.
 * Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".
 *
 * Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the
 * original plaintext; the attacker has the ciphertext and controls the offset and "new text".
 *
 * Recover the original plaintext.
 */
@Slf4j
public class C25 {

    private static final byte[] KEY = ByteArrayUtil.randomBytes(16);
    private final CTR ctr = new CTR(KEY);

    private static final byte[] CBC_KEY = "YELLOW SUBMARINE".getBytes();
    private final ECB ecb = new ECB(CBC_KEY);

    private final XOR xor = new XOR();

    /**
     * test the edit function before we complete the challenge
     */
    @Test
    void testEditing() {
        //encrypt the plaintext
        final String plaintext = getPlainTextFromFile();
        var ciphertext = ctr.encrypt(plaintext);
        /* ------------------------------------- */

        //edit the plaintext
        final String monkey = "monkey";
        ctr.edit(ciphertext, 6, monkey);

        var decrypted = ctr.decrypt(ciphertext);
        assertEquals("monkey", decrypted.substring(6, 6 + monkey.length()));
    }

    /**
     * complete the challenge
     */
    @Test
    void recoverThePlainText() {
        final String plaintext = getPlainTextFromFile();
        final byte[] cipherText = ctr.encrypt(plaintext);
        /*------------------------------------------*/

        //we can get the keystream out of the edit function by
        // passing in all 0s
        final String breakerString = new String(new byte[cipherText.length]);

        //copy the cipherText so we retain original
        final byte[] keystream = ArrayUtils.clone(cipherText);

        //edit the copy with the breaker string to get the keystream
        ctr.edit(keystream, 0, breakerString);

        //once we have the keystream, we can simply xor it against the cipherText to recover the plaintext
        final String broken = new String(xor.multiByteXOR(cipherText, keystream));

        assertEquals(plaintext, broken);
    }

    /**
     * read the file out as a single string and decrypting using ecb
     * the string join portion is a candidate for movement into the file util if repeatedly needed
     * @return plain text
     */
    private String getPlainTextFromFile() {
        final String b64 = String.join("", FileUtil.readFileAsListOfLines("src/test/resources/25.txt"));
        var decoded = Base64.getDecoder().decode(b64);
        return new String(ecb.AES(decoded, CipherMode.DECRYPT));
    }


}
