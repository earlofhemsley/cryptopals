package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.Profile;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * ECB cut-and-paste
 *
 * Write a k=v parsing routine, as if for a structured cookie. The routine should take:
 *
 * foo=bar&baz=qux&zap=zazzle
 * ... and produce:
 *
 * {
 *   foo: 'bar',
 *   baz: 'qux',
 *   zap: 'zazzle'
 * }
 * (you know, the object; I don't care if you convert it to JSON).
 *
 * Now write a function that encodes a user profile in that format, given an email address.
 * You should have something like:
 *
 * profile_for("foo@bar.com")
 * ... and it should produce:
 *
 * {
 *   email: 'foo@bar.com',
 *   uid: 10,
 *   role: 'user'
 * }
 * ... encoded as:
 *
 * email=foo@bar.com&uid=10&role=user
 * Your "profile_for" function should not allow encoding metacharacters (& and =).
 * Eat them, quote them, whatever you want to do, but don't let people set their email address
 * to "foo@bar.com&role=admin".
 *
 * Now, two more easy functions. Generate a random AES key, then:
 *
 * Encrypt the encoded user profile under the key; "provide" that to the "attacker".
 * Decrypt the encoded user profile and parse it.
 * Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
 * and the ciphertexts themselves, make a role=admin profile.
 */
public class C13 {
    @Test
    public void testChallenge13() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        //test kv parsing method
        var kvString = "foo=bar&baz=qux&zap=zazzle";
        var objectMap = Profile.keyValueParsing(kvString);
        assertEquals("bar", objectMap.get("foo"));
        assertEquals("qux", objectMap.get("baz"));
        assertEquals("zazzle", objectMap.get("zap"));

        //test user profile encoding method
        var naughtyProfile = new Profile("foo@bar.com&role=admin");
        assertEquals("email=foo@bar.comroleadmin&uid=10&role=user", naughtyProfile.profileFor());

        //send a profile off to be hacked into an admin profile
        String string = "AAAAAAAAAAadmin" + String.valueOf((char) 11).repeat(11) + "AAA";
        var profile = new Profile(string);
        var encryptedProfile = profile.encryptProfile();
        assert encryptedProfile.length == 16*4;
        var block1 = ArrayUtils.subarray(encryptedProfile, 0, 16);
        var block2 = ArrayUtils.subarray(encryptedProfile, 16, 32);
        var block3 = ArrayUtils.subarray(encryptedProfile, 32, 48);
        var hackedInput = ArrayUtils.addAll(block1, ArrayUtils.addAll(block3, block2));
        var decryptedAndParsed = new Profile(hackedInput);
        assertEquals("admin", decryptedAndParsed.get("role"));
    }
}
