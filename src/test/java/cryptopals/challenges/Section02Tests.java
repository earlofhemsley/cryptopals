package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
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
    public void testChallenge10() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, IOException {
        String lorem = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s";
        String key = "YELLOW SUBMARINE";
        byte[] iv = new byte[key.length()];

        byte[] enc = Section02.AESinCBCMode(lorem.getBytes(), key.getBytes(), iv, Cipher.ENCRYPT_MODE);
        String loremPost = new String(Section02.AESinCBCMode(enc, key.getBytes(), iv, Cipher.DECRYPT_MODE));
        assertEquals(lorem, loremPost);

        String base64Contents = String.join("", Utils.readFileAsListOfLines("src/test/resources/10.txt"));
        byte[] fileContents = Base64.getDecoder().decode(base64Contents);
        byte[] decryptedFileContents = Section02.AESinCBCMode(fileContents, key.getBytes(), iv, Cipher.DECRYPT_MODE);

        //sanity check
        byte[] reEncryptedFileContents = Section02.AESinCBCMode(decryptedFileContents, key.getBytes(), iv, Cipher.ENCRYPT_MODE);
        assertArrayEquals(fileContents, reEncryptedFileContents);

        assertTrue(new String(decryptedFileContents).contains("You're weakenin' fast, YO! and I can tell it"));
    }

    @Test
    public void testChallenge11() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, DecoderException {
        String myHackerInput = "Acknowledgement Acknowledgement Acknowledgement Lorem Ipsum is simply dummy text of the printing and typesetting industry.";
        for(int i = 0; i<1000; i++) {
            var result = Section02.encryptionOracleUnknownMode(myHackerInput.getBytes());
            boolean ecbDetected = Section01.detectECBInCipherBytes(result.getRight(), "1234567890123456".getBytes());
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
        var naughtyProfile = Section02.userProfileEncoding("foo@bar.com&role=admin");
        assertEquals("email=foo@bar.comroleadmin&uid=10&role=user", naughtyProfile);

        //generate random key
        var key = Utils.randomBytes(16);

        //give the key to the hacker ... that's me! yay!
        //encrypt the profile with the key
        //generate a profile

        //send the encrypted profile off to be hacked into an admin profile
        String hacked = Section02.hackAUserProfile(key);

        var hackedMap = Section02.keyValueParsing(hacked);
        assertEquals("admin", hackedMap.get("role"));
    }
}
