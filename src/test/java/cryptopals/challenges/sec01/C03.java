package cryptopals.challenges.sec01;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import cryptopals.tool.sec01.Challenge3Tool;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

/**
 * Single-byte XOR cipher
 * The hex encoded string:
 *
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 * ... has been XOR'd against a single character. Find the key, decrypt the message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
 *
 * Achievement Unlocked
 * You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
 */
public class C03 {
    @Test
    public void threeTest() throws DecoderException {
        String value = Challenge3Tool.decrypt(Hex.decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
        assertEquals("Cooking MC's like a pound of bacon", value);
    }
}
