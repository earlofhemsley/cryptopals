package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import cryptopals.tool.SHA1;
import cryptopals.tool.sec04.C29_Sha1Breaker;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Break a SHA-1 keyed MAC using length extension
 * Secret-prefix SHA-1 MACs are trivially breakable.
 *
 * The attack on secret-prefix SHA1 relies on the fact that you can take the output of SHA-1 and use it as a new
 * starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
 *
 * Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will
 * appear to have been hashed with the secret key.
 *
 * To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the
 * message; your forged message will need to include that padding. We call this "glue padding".
 *
 * The final message you actually forge will be:
 * SHA1(key || original-message || glue-padding || new-message)
 * (where the final padding on the whole constructed message is implied)
 *
 * Note that to generate the glue padding, you'll need to know the original bit length of the message; the message
 * itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
 *
 * This sounds more complicated than it is in practice.
 *
 * To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify
 * that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.
 *
 * Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash ---
 * and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", etc).
 *
 * Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c
 * (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.
 *
 * Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from
 * /usr/share/dict/words or something) of the string:
 *
 * "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
 * Forge a variant of this message that ends with ";admin=true".
 *
 * This is a very useful attack.
 * For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
 */
@Slf4j
public class C29 {

    private final SHA1 sha1 = new SHA1();
    private final C29_Sha1Breaker breaker = new C29_Sha1Breaker(sha1);


    @ParameterizedTest
    @MethodSource("supplyPaddingArgs")
    void buildMDPadding(final byte[] msg, final int expectedPadLength) {
        final byte[] padding = breaker.buildGluePadding(msg);
        assertEquals(expectedPadLength, padding.length);
        assertEquals(Byte.MIN_VALUE, padding[0]);
        //multiply by 8 because bit length, not byte length
        assertEquals(msg.length * 8L, unpackCharCount(padding));
    }

    static Stream<Arguments> supplyPaddingArgs() {
        return Stream.of(
                arguments("1234567890".getBytes(), 54),
                arguments("1234567890123456789012345678901234567890123456789012345".getBytes(), 73),
                arguments("123456789012345678901234567890123456789012345678901234567890123".getBytes(), 65),
                arguments("1234567890123456789012345678901234567890123456789012345678901234".getBytes(), 64),
                arguments("12345678901234567890123456789012345678901234567890123456789012345".getBytes(), 63)
        );
    }

    private long unpackCharCount(final byte[] padding) {
        //only need to unpack the last four bytes
        // that's all the bytes there are in an int
        long count = 0;
        for (int i = 0; i < 8; i++) {
            count |= (padding[padding.length - 1 - i] & (long) 0xff) << (i * 8);
        }
        return count;
    }

    @Test
    void completeTheChallenge() {
        //we don't know how long the key is
        //start at one character and stop at 20
        final byte[] subject = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".getBytes();
        final byte[] appendix = ";admin=true".getBytes();

        //get the hash for this string
        final byte[] hash = sha1.getMAC(subject);

        for (int keyLength = 1; keyLength <= 128; keyLength++) {
            final byte[] fakeKey = new byte[keyLength];
            Arrays.fill(fakeKey, (byte) 'A');

            //this hash is actually a hash of another string. We need to get the padding for the subject prefixed with a
            // string of a certain length
            final byte[] padding = breaker.buildGluePadding(ByteArrayUtil.concatenate(fakeKey, subject));

            //now that we have the padding, we should be able to reset the state without knowing the private key
            // to key || message || padding and then continue to process the appended thing,
            final int byteCountOverride = fakeKey.length + subject.length + padding.length;
            final byte[] newHash = breaker.breakIt(hash, byteCountOverride, appendix);

            // and we should be able to
            // authenticate that the hash we get is valid for message || padding || new
            final byte[] forgedMessage = ByteArrayUtil.concatenate(subject,
                    ByteArrayUtil.concatenate(padding, appendix));

            if (sha1.authenticateMessage(forgedMessage, newHash)) {
                log.info("Forgery was successful. The key length was {}", keyLength);
                return;
            }
        }
        fail("Message authentication failed for all key lengths 1 to 20");
    }
}
