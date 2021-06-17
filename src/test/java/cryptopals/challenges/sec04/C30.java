package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.fail;

import cryptopals.tool.MD4;
import cryptopals.tool.sec04.C30_MD4Breaker;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * Break an MD4 keyed MAC using length extension
 * Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1,
 * the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
 *
 * You're thinking, why did we bother with this?
 * Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1.
 * Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
 */
@Slf4j
public class C30 {

    private final MD4 md4 = new MD4();
    private final C30_MD4Breaker breaker = new C30_MD4Breaker(md4);

    @Test
    void completeTheChallenge() {
        final byte[] subject = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".getBytes();
        final byte[] appendix = ";admin=true".getBytes();
        final byte[] hash = md4.getMAC(subject);

        //right now this is failing. i've got to
        // - verify that the padding looks correct
        // - verify that the state is reset properly
        // - verify that the bitcount is being reset like it should
        // - find where the gap is
        for (int keyLength = 1; keyLength <= 20; keyLength++) {
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

            if (md4.authenticateMessage(forgedMessage, newHash)) {
                log.info("Forgery was successful. The key length was {}", keyLength);
                return;
            }
        }
        fail("Message authentication failed for all key lengths 1 to 20");
    }
}
