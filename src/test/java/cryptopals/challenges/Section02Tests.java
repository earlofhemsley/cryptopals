package cryptopals.challenges;

import static cryptopals.challenges.Section02.AESinCBCMode;
import static cryptopals.challenges.Section02.implementPKCS7Padding;
import static cryptopals.challenges.Section02.stripPCKS7Padding;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.collect.Lists;
import cryptopals.enums.CipherMode;
import cryptopals.exceptions.BadPaddingRuntimeException;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.utils.Challenge16Oracle;
import cryptopals.utils.ECB;
import cryptopals.utils.Utils;
import cryptopals.utils.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Section02Tests {
    @Test
    public void implementPKCS7PaddingTest() {
        String testString = "YELLOW SUBMARINE";
        byte[] result = Section02.implementPKCS7Padding(testString.getBytes(), 20);
        String expected = testString + (char) 4 + (char) 4 + (char) 4 + (char) 4;
        assertArrayEquals(expected.getBytes(), result);

        result = Section02.implementPKCS7Padding(testString.getBytes(), 3);
        expected = testString + (char) 2 + (char) 2;
        assertArrayEquals(expected.getBytes(), result);

        result = Section02.implementPKCS7Padding(testString.getBytes(), 4);
        expected = testString + (char) 4 + (char) 4 + (char) 4 + (char) 4;
        assertArrayEquals(expected.getBytes(), result);
    }


    @Test
    public void testChallenge10() throws IOException {
        String lorem = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s";
        String key = "YELLOW SUBMARINE";
        byte[] iv = new byte[key.length()];

        byte[] enc = AESinCBCMode(Section02.implementPKCS7Padding(lorem.getBytes(), key.length()), key.getBytes(), iv, CipherMode.ENCRYPT);
        String loremPost = new String(stripPCKS7Padding(AESinCBCMode(enc, key.getBytes(), iv, CipherMode.DECRYPT)));
        assertEquals(lorem, loremPost);

        String base64Contents = String.join("", Utils.readFileAsListOfLines("src/test/resources/10.txt"));
        byte[] fileContents = Base64.getDecoder().decode(base64Contents);
        byte[] decryptedFileContents = stripPCKS7Padding(AESinCBCMode(fileContents, key.getBytes(), iv, CipherMode.DECRYPT));

        //sanity check
        byte[] reEncryptedFileContents = AESinCBCMode(implementPKCS7Padding(decryptedFileContents, key.length()), key.getBytes(), iv, CipherMode.ENCRYPT);
        assertArrayEquals(fileContents, reEncryptedFileContents);

        assertTrue(new String(decryptedFileContents).contains("You're weakenin' fast, YO! and I can tell it"));
    }

    @Test
    public void testChallenge11() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, DecoderException {
        String myHackerInput = "Acknowledgement Acknowledgement Acknowledgement Lorem Ipsum is simply dummy text of the printing and typesetting industry.";
        for(int i = 0; i<1000; i++) {
            var result = Section02.encryptionOracleUnknownMode(myHackerInput.getBytes());
            boolean ecbDetected = new ECB("1234567890123456".getBytes()).detectECBInCipherBytes(result.getRight());
            assertEquals(result.getLeft(), ecbDetected);
        }
    }

    @Test
    public void testChallenge12() throws DecoderException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        String unknownInput = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
        "YnkK";

        byte[] unknownInputDecoded = Base64.getDecoder().decode(unknownInput.getBytes());
        byte[] decrypted = Section02.breakECBEncryptionUsingOracle(unknownInputDecoded);
        assertArrayEquals(unknownInputDecoded, decrypted);
    }

    @Test
    public void testChallenge13() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        //test kv parsing method
        var kvString = "foo=bar&baz=qux&zap=zazzle";
        var objectMap = Section02.keyValueParsing(kvString);
        assertEquals("bar", objectMap.get("foo"));
        assertEquals("qux", objectMap.get("baz"));
        assertEquals("zazzle", objectMap.get("zap"));

        //test user profile encoding method
        var naughtyProfile = Section02.profileFor("foo@bar.com&role=admin");
        assertEquals("email=foo@bar.comroleadmin&uid=10&role=user", naughtyProfile);

        //send a profile off to be hacked into an admin profile
        String string = "AAAAAAAAAAadmin" + String.valueOf((char) 11).repeat(11) + "AAA";
        var profile = Section02.profileFor(string);
        var encryptedProfile = Section02.encryptProfile(profile);
        assert encryptedProfile.length == 16*4;
        var block1 = ArrayUtils.subarray(encryptedProfile, 0, 16);
        var block2 = ArrayUtils.subarray(encryptedProfile, 16, 32);
        var block3 = ArrayUtils.subarray(encryptedProfile, 32, 48);
        var hackedInput = ArrayUtils.addAll(block1, ArrayUtils.addAll(block3, block2));
        var decryptedAndParsed = Section02.decryptAndParse(hackedInput);
        assertEquals("admin", decryptedAndParsed.get("role"));
    }

    @Test
    public void testChallenge14() throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException {
        String unknownInput = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK";

        byte[] unknownInputDecoded = Base64.getDecoder().decode(unknownInput.getBytes());
        byte[] decrypted = Section02.breakECBEncryptionWithPrefixUsingOracle(unknownInputDecoded);
        assertArrayEquals(unknownInputDecoded, decrypted);
    }

    @Test
    public void testChallenge15() throws BadPaddingException {
        assertArrayEquals("ICE ICE BABY".getBytes(), stripPCKS7Padding(generatePaddingSample(new byte[] {4,4,4,4})));
        assertThrows(BadPaddingRuntimeException.class, () -> stripPCKS7Padding(generatePaddingSample(new byte[] {5,5,5,5})));
        assertThrows(BadPaddingRuntimeException.class, () -> stripPCKS7Padding(generatePaddingSample(new byte[] {1,2,3,4})));
    }

    private static byte[] generatePaddingSample(byte[] paddingBytes) {
        String sb = "ICE ICE BABY" +
                new String(paddingBytes);
        return sb.getBytes();
    }

    @Test
    public void testChallenge16() throws Exception {
        var key = Utils.randomBytes(16);
        var iv = Utils.randomBytes(16);
        var oracle = new Challenge16Oracle(key, iv);
        //comment1=cooking|%20MCs;userdata=|AAAAAAAAAAAAAAAA|:admin<true:A<AA|;comment2=...
        String knownInput = "7admin9true7A9AA";
        String desired = ";admin=true;A=AA";
        assertEquals(16, knownInput.length());
        assertEquals(16, desired.length());

        final XOR xor = new XOR();
        byte[] xord = xor.multiByteXOR(knownInput.getBytes(), desired.getBytes());
        assertArrayEquals(desired.getBytes(), xor.multiByteXOR(knownInput.getBytes(), xord));
        assertArrayEquals(knownInput.getBytes(), xor.multiByteXOR(desired.getBytes(), xord));

        List<Integer> positionsOf12 = Lists.newArrayList(0, 11);
        List<Integer> positionsOf4 = Lists.newArrayList(6, 13);
        for (int i =0; i<xord.length; i++) {
            if (positionsOf4.contains(i)) {
                assertEquals(4, xord[i]);
            } else if (positionsOf12.contains(i)) {
                assertEquals(12, xord[i]);
            } else {
                assertEquals(0, xord[i]);
            }
        }

        //prepend with a block that we don't care if it gets scrambled
        knownInput = "AAAAAAAAAAAAAAAA" + knownInput;

        var cipherText = oracle.padAndEncrypt(knownInput);

        assertFalse(oracle.findAdminInCipherText(cipherText));

        var textToAlter = Utils.sliceByteArray(cipherText, 32, xord.length);
        var alteredText = xor.multiByteXOR(textToAlter, xord);

        assertArrayEquals(textToAlter, xor.multiByteXOR(alteredText, xord));
        assertArrayEquals(xord, xor.multiByteXOR(textToAlter, alteredText));
        System.arraycopy(alteredText, 0, cipherText, 32, alteredText.length);

        assertTrue(oracle.findAdminInCipherText(cipherText));
    }
}
