package cryptopals.challenges.sec01;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.sec01.Challenge5Tool;
import cryptopals.utils.FileUtil;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * Implement repeating-key XOR
 * Here is the opening stanza of an important work of the English language:
 *
 * Burning 'em, if you ain't quick and nimble
 * I go crazy when I hear a cymbal
 * Encrypt it, under the key "ICE", using repeating-key XOR.
 *
 * In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
 *
 * It should come out to:
 *
 * 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
 * a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
 * Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
 */
public class C05 {
    @Test
    public void fiveTest() throws DecoderException {
        Challenge5Tool tool = new Challenge5Tool("ICE".getBytes());
        String toEncrypt = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";
        var result = tool.repeatingKeyEncrypt(toEncrypt);
        var expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assertEquals(expected, result);

        var bloodContents = FileUtil.readFileAsWhole("src/test/resources/blood");
        var singleStringBloodContents = String.join("\n", bloodContents);

        encryptAndOutputAndDecryptAndOutput(tool, singleStringBloodContents, false);
        encryptAndOutputAndDecryptAndOutput(tool, FileUtil.readFileAsWhole("src/test/resources/enid.jok"), false);
        encryptAndOutputAndDecryptAndOutput(tool, FileUtil.readFileAsWhole("src/test/resources/einstein"), false);
        encryptAndOutputAndDecryptAndOutput(tool, FileUtil.readFileAsWhole("src/test/resources/spock.txt"), true);
    }

    private void encryptAndOutputAndDecryptAndOutput(Challenge5Tool tool, String original, boolean print) throws DecoderException {
        var encrypted = tool.repeatingKeyEncrypt(original);
        var decrypted = tool.repeatingKeyDecrypt(encrypted);

        assertEquals(original, decrypted);

        if(print) {
            System.out.println(encrypted);
            System.out.println(decrypted);
        }
    }
}
