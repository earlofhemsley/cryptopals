package cryptopals.challenges.sec01;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.sec01.Challenge4Tool;
import cryptopals.utils.FileUtil;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

/**
 * Detect single-character XOR
 * One of the 60-character strings in this file has been encrypted by single-character XOR.
 *
 * Find it.
 *
 * (Your code from #3 should help.)
 */
public class C04 {
    @Test
    public void fourTest() throws DecoderException, IOException {
        String filePath = "src/test/resources/4.txt";
        List<String> contents = FileUtil.readFileAsListOfLines(filePath);
        String value = new Challenge4Tool().seekAndDestroy(contents);
        assertEquals("Now that the party is jumping", value);
    }

}
