package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.enums.CipherMode;
import cryptopals.sec01.util.Challenge4Tool;
import cryptopals.sec01.util.Challenge5Tool;
import cryptopals.sec01.util.Challenge6Tool;
import cryptopals.utils.ECB;
import cryptopals.utils.Utils;
import cryptopals.utils.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Section01Tests {

    @Test
    public void oneTest() throws DecoderException {
        String input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String result = Section01.convertHexToBase64(input);
        assertEquals("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", result);
        String reconverted = Hex.encodeHexString(Base64.getDecoder().decode(result));
        assertEquals(input, reconverted);
    }

    @Test
    public void twoTest() throws DecoderException {
        String input1 = "1c0111001f010100061a024b53535009181c";
        String input2 = "686974207468652062756c6c277320657965";
        String result = new XOR().hexStringFixedXor(input1, input2);
        assertEquals("746865206b696420646f6e277420706c6179", result);
    }

    @Test
    public void threeTest() throws DecoderException {
        String value = Section01.decrypt(Hex.decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
        assertNotNull(value);
        assertEquals("Cooking MC's like a pound of bacon", value);
    }

    @Test
    public void fourTest() throws DecoderException, IOException {
        String filePath = "src/test/resources/4.txt";
        List<String> contents = Utils.readFileAsListOfLines(filePath);
        String value = new Challenge4Tool().seekAndDestroy(contents);
        assertEquals("Now that the party is jumping", value);
    }

    @Test
    public void fiveTest() throws IOException, DecoderException {
        Challenge5Tool tool = new Challenge5Tool("ICE".getBytes());
        String toEncrypt = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";
        var result = tool.repeatingKeyEncrypt(toEncrypt);
        var expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assertEquals(expected, result);

        var bloodContents = Utils.readFileAsWhole("src/test/resources/blood");
        var singleStringBloodContents = String.join("\n", bloodContents);

        encryptAndOutputAndDecryptAndOutput(tool, singleStringBloodContents, false);
        encryptAndOutputAndDecryptAndOutput(tool, Utils.readFileAsWhole("src/test/resources/enid.jok"), false);
        encryptAndOutputAndDecryptAndOutput(tool, Utils.readFileAsWhole("src/test/resources/einstein"), false);
        encryptAndOutputAndDecryptAndOutput(tool, Utils.readFileAsWhole("src/test/resources/spock.txt"), true);
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

    @Test
    public void sixTest() throws IOException {
        String first = "this is a test";
        String second = "wokka wokka!!!";
        int hamming = Utils.calculateHammingDistance(first.getBytes(), second.getBytes());
        assertEquals(37, hamming);

        //read the file contents into a single string
        var fileContents = Utils.readFileAsListOfLines("src/test/resources/6.txt");
        var joinedContents = String.join("", fileContents);

        String decrypted = Challenge6Tool.breakTheCipher(joinedContents);
        System.out.println(decrypted);
        assertTrue(decrypted.contains("I'm back and I'm ringin' the bell"));
    }

    @Test
    public void sevenTest() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        String cipherKey = "YELLOW SUBMARINE";
        assertEquals(16, cipherKey.length());

        var fileContents = String.join("", Utils.readFileAsListOfLines("src/test/resources/7.txt"));
        byte[] cipherTextBytes = Base64.getDecoder().decode(fileContents);
        byte[] decrypted = new ECB(cipherKey.getBytes()).AESInECBMode(cipherTextBytes, CipherMode.DECRYPT);
        assertTrue(new String(decrypted).contains("I'm back and I'm ringin' the bell"));
    }

    @Test
    public void eightTest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, DecoderException, BadPaddingException, IllegalBlockSizeException {
        var fileContents = Utils.readFileAsListOfLines("src/test/resources/8.txt");
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
