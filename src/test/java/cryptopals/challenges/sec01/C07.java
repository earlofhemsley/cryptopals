package cryptopals.challenges.sec01;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.enums.CipherMode;
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
        byte[] key = "ABCDEFGHIJKLMNOP".getBytes();
        final var fileBytes = FileUtil.readFileAsByteArray("src/test/resources/7-XC.bmp");

        //find where we should start in order to match the image byte array to the key
        int offset = -1;
        for (int i = fileBytes.length; i >= 0; i--) {
            if (i % key.length == 0) {
                offset = fileBytes.length - i;
                break;
            }
        }
        assertNotEquals(-1, offset);

        //get the last n bytes from the image data, where n is the length of the image data less the offset
        var encryptable = ByteArrayUtil.sliceEnd(fileBytes, fileBytes.length - offset);
        //retain the first 54 bytes of the image so that we can overwrite the first 54 bytes of bmp header data
        var header = ByteArrayUtil.sliceByteArray(fileBytes, 0, 54);

        //do the encryption
        byte[] encrypted = new ECB(key).AES128(encryptable, CipherMode.ENCRYPT);

        // write the encrypted data into a new array that will be written to disk
        var encryptedImageData = new byte[fileBytes.length];
        for (int i = encryptedImageData.length - 1, j = encrypted.length - 1; j >= 0;) {
            encryptedImageData[i] = encrypted[j];
            i--; j--;
        }
        System.arraycopy(header, 0, encryptedImageData, 0, header.length);

        assertTrue(FileUtil.writeFile("src/test/resources/7-XC-ENC.bmp", encryptedImageData));
    }
}