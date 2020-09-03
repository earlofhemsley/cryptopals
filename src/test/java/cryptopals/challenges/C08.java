package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import cryptopals.tool.ECB;
import cryptopals.utils.FileUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Detect AES in ECB mode
 *
 * In this file are a bunch of hex-encoded ciphertexts.
 *
 * One of them has been encrypted with ECB.
 *
 * Detect it.
 *
 * Remember that the problem with ECB is that it is stateless and deterministic;
 * the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
 */
public class C08 {
    @Test
    public void eightTest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, DecoderException, BadPaddingException, IllegalBlockSizeException {
        var fileContents = FileUtil.readFileAsListOfLines("src/test/resources/8.txt");
        Integer rowNumber = null;
        for (int i = 0; i < fileContents.size(); i++) {
            //hex decode
            byte[] decodedRow = Hex.decodeHex(fileContents.get(i));

            //run detection
            if(new ECB("1234567890123456".getBytes()).detectECBInCipherBytes(decodedRow)) {
                rowNumber = i;
                break;
            }
        }
        assertNotNull(rowNumber);
        assertEquals(132, rowNumber);
    }
}
