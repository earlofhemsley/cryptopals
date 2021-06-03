package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import cryptopals.exceptions.ECBException;
import cryptopals.tool.CBC;
import cryptopals.tool.CTR;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.FileUtil;
import lombok.extern.slf4j.Slf4j;
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
    private final CBC cbc = new CBC(CBC_KEY);

    @Test
    void testEditing() throws IOException, ECBException {
        //encrypt the plaintext
        var b64 = String.join("", FileUtil.readFileAsListOfLines("src/test/resources/10.txt"));
        var decoded = Base64.getDecoder().decode(b64);
        var plaintext = cbc.decryptAsString(decoded, new byte[CBC_KEY.length]);
        var ciphertext = ctr.encrypt(plaintext);
        /* ------------------------------------- */

        //edit the plaintext
        final String monkey = "monkey";
        final var edited = ctr.edit(ciphertext, 6, monkey);

        var decrypted = ctr.decrypt(edited);
        assertEquals("monkey", decrypted.substring(6, 6 + monkey.length()));
    }
}
