package cryptopals.challenges;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SectionOneTests {

    @Test
    public void oneTest() throws DecoderException {
        String input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String result = One.convertHexToBase64(input);
        assertEquals("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", result);
    }

    @Test
    public void twoTest() throws DecoderException {
        String input1 = "1c0111001f010100061a024b53535009181c";
        String input2 = "686974207468652062756c6c277320657965";
        String result = Two.fixedXOR(input1, input2);
        assertEquals("746865206b696420646f6e277420706c6179", result);
    }

    @Test
    public void threeTest() throws DecoderException {
        String value = Three.decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assertNotNull(value);
        assertEquals("Cooking MC's like a pound of bacon", value);
    }

    @Test
    public void fourTest() throws DecoderException, IOException {
        List<String> contents = getFileContentsAsStringList("src/test/resources/4.txt");
        String value = Four.seekAndDestroy(contents);
        assertEquals("Now that the party is jumping", value);
    }

    private List<String> getFileContentsAsStringList(String filePath) throws IOException {
        List<String> retVal = new ArrayList<>();
        File f = new File(filePath);

        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line;
            while((line = r.readLine()) != null) {
                retVal.add(line.strip());
            }
        }
        return retVal;
    }
}
