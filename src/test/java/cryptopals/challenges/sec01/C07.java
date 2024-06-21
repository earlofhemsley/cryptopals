package cryptopals.challenges.sec01;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.enums.CipherMode;
import cryptopals.tool.BitmapCipherTool;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.FileUtil;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES in ECB mode
 * The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
 *
 * "YELLOW SUBMARINE".
 * (case-sensitive, without the quotes; exactly 16 characters;
 * I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
 *
 * Decrypt it. You know the key, after all.
 *
 * Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
 *
 * Do this with code.
 * You can obviously decrypt this using the OpenSSL command-line tool,
 * but we're having you get ECB working in code for a reason.
 * You'll need it a lot later on, and not just for attacking ECB.
 */
public class C07 {
    @Test
    public void sevenTest() {
        String cipherKey = "YELLOW SUBMARINE";
        assertEquals(16, cipherKey.length());

        String fileContents = String.join("", FileUtil.readFileAsListOfLines("src/test/resources/7.txt"));
        byte[] cipherTextBytes = Base64.getDecoder().decode(fileContents);
        byte[] decrypted = new ECB(cipherKey.getBytes()).AES128(cipherTextBytes, CipherMode.DECRYPT);
        assertTrue(new String(decrypted).contains("I'm back and I'm ringin' the bell"));
    }

    /**
     *
     */
    @Test
    public void extraCredit_encryptAnImage() {
        String key = "ABCDEFGHIJKLMNOP";
        BitmapCipherTool.EncryptBitmapImage("src/test/resources/7-XC.bmp", key, false);
    }
}