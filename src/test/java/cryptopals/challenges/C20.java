package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.CTR;
import cryptopals.tool.XOR;
import cryptopals.tool.sec03.Challenge20Tool;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.FileUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Break fixed-nonce CTR statistically
 * In this file (saved at src/test/resources/20.txt) find a similar set of Base64'd plaintext.
 * Do with them exactly what you did with the first, but solve the problem differently.
 *
 * Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts
 * the same way you would repeating-key XOR.
 *
 * Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce
 * they are effectively the same thing.
 *
 * To exploit this: take your collection of ciphertexts and truncate them to a common length
 * (the length of the smallest ciphertext will work).
 *
 * Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key
 * size of the length of the ciphertext you XOR'd.
 */
public class C20 {
    private static final byte[] CIPHER_KEY = ByteArrayUtil.randomBytes(16,
            "AS ARMAS AS ARMAS SOBRE A TERRA SOBRE O MAR");
    private final CTR ctr = new CTR(CIPHER_KEY);
    private final XOR xor = new XOR();

    @Test
    public void findTheKeyStream() throws IOException {
        final String[] plainTexts = readFileIntoPlainTexts();
        final byte[][] cipherTexts = Arrays.stream(plainTexts).map(ctr::encrypt).toArray(byte[][]::new);
        final byte[] keyStream = new Challenge20Tool().findTheKeyStream(cipherTexts);

        for (int i = 0; i < cipherTexts.length; i++) {
            var decrypted = new String(xor.multiByteXOR(cipherTexts[i], keyStream));
            System.out.println(decrypted);
            assertEquals(plainTexts[i], decrypted);
        }
    }

    private String[] readFileIntoPlainTexts() throws IOException {
        return FileUtil.readFileAsListOfLines("src/test/resources/20.txt").stream()
                .map(s -> Base64.getDecoder().decode(s))
                .map(String::new)
                .toArray(String[]::new);
    }

}
