package cryptopals.challenges.sec02;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.CBC;
import cryptopals.utils.FileUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Base64;

/**
 * Implement CBC mode
 *
 * CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
 * despite the fact that a block cipher natively only transforms individual blocks.
 *
 * In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
 *
 * The first plaintext block, which has no associated previous ciphertext block,
 * is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
 *
 * Implement CBC mode by hand by taking the ECB function you wrote earlier,
 * making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
 * and using your XOR function from the previous exercise to combine them.
 *
 * The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE"
 * with an IV of all ASCII 0 (\x00\x00\x00 &c)
 *
 * Don't cheat.
 *
 * Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
 * What's the point of even doing this stuff if you aren't going to learn from it?
 */
public class C10 {
    @Test
    public void testChallenge10() throws IOException {
        String lorem = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s";
        String key = "YELLOW SUBMARINE";
        final CBC cbc = new CBC(key.getBytes());
        byte[] iv = new byte[key.length()];

        byte[] enc = cbc.encryptToByteArray(lorem.getBytes(), iv);
        String loremPost = cbc.decryptAsString(enc, iv);
        assertEquals(lorem, loremPost);

        String base64Contents = String.join("", FileUtil.readFileAsListOfLines("src/test/resources/10.txt"));
        byte[] fileContents = Base64.getDecoder().decode(base64Contents);
        byte[] decryptedFileContents = cbc.decryptAsByteArray(fileContents, iv);

        //sanity check
        byte[] reEncryptedFileContents = cbc.encryptToByteArray(decryptedFileContents, iv);
        assertArrayEquals(fileContents, reEncryptedFileContents);

        assertTrue(new String(decryptedFileContents).contains("You're weakenin' fast, YO! and I can tell it"));
    }
}
