package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import cryptopals.tool.SHA1;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Field;
import java.util.stream.Stream;

/**
 * Implement a SHA-1 keyed MAC
 * Find a SHA-1 implementation in the language you code in.
 *
 * Don't cheat. It won't work.
 * Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
 *
 * Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
 *
 * SHA1(key || message)
 *
 * Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
 */
public class C28 {

    @ParameterizedTest
    @MethodSource("supplyIllegalArgs")
    void illegalArgumentsTests(final String message, final String mac, final String expectedBadParam) {
        final SHA1 sha1 = new SHA1();
        final var key = extractPrivateKey(sha1);
        var ex = assertThrows(IllegalArgumentException.class, () -> sha1.authenticateMessage(key, message, mac));
        assertTrue(ex.getMessage().contains(expectedBadParam));
    }

    static Stream<Arguments> supplyIllegalArgs() {
        return Stream.of(
                arguments(null, "1234567890123456789012345678901234567890", "message"),
                arguments("", "1234567890123456789012345678901234567890", "message"),
                arguments(" ", "1234567890123456789012345678901234567890", "message"),
                arguments("hey", null, "mac"),
                arguments("hey", "", "mac"),
                arguments("hey", " ", "mac"),
                arguments("hey", "123456789012345678901234567890123456789", "mac")
        );
    }

    /**
     * test that the same message hashed twice gives the same mac
     */
    @Test
    void verifyHashingIsDeterministic() {
        final SHA1 sha1 = new SHA1();
        final String myMessage = "Hello World!";
        final String hash = sha1.getMAC(myMessage);
        final String hash2 = sha1.getMAC(myMessage);
        assertEquals(hash, hash2);
    }

    /**
     * test that a message can be authenticated when you know the private key
     */
    @Test
    void verifyMessageHashAgainstItself() {
        final SHA1 sha1 = new SHA1();
        final String myMessage = "Hello World!";
        final String hash = sha1.getMAC(myMessage);
        final var key = extractPrivateKey(sha1);
        assertTrue(sha1.authenticateMessage(key, myMessage, hash));
    }

    /**
     * test that changing the message will make it impossible to authenticate a mac
     */
    @Test
    void verifyChangeInMessageIsChangeInMac() {
        final SHA1 sha1 = new SHA1();
        final String myMessage = "Hello";
        final String hash = sha1.getMAC(myMessage);
        final var key = extractPrivateKey(sha1);
        assertFalse(sha1.authenticateMessage(key, "hello", hash));
    }

    /**
     * test that not knowing the key will make it impossible to authenticate a mac
     */
    @Test
    void verifyNotKnowingTheKeyWillBork() {
        final SHA1 sha1 = new SHA1();
        final String myMessage = "Hello";
        final String hash = sha1.getMAC(myMessage);
        assertFalse(sha1.authenticateMessage(new byte[11], myMessage, hash));
    }

    /**
     * unless you know the key, you can't authenticate the message
     * @param instance an instance of sha
     * @return the key
     */
    @SneakyThrows
    private byte[] extractPrivateKey(final SHA1 instance) {
        Field f = SHA1.class.getDeclaredField("privateKey");
        f.setAccessible(true);
        return (byte[]) f.get(instance);
    }
}
