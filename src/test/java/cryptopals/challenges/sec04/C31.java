package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import cryptopals.tool.SHA1;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.junit.jupiter.api.Test;

/**
 * Implement and break HMAC-SHA1 with an artificial timing leak
 * The psuedocode on Wikipedia should be enough. HMAC is very easy.
 *
 * Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that
 * takes a "file" argument and a "signature" argument, like so:
 *
 * http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
 * Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file",
 * using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words,
 * verify the HMAC the way any normal programmer would verify it).
 *
 * Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time
 * comparisons with early exit (ie, return false at the first non-matching byte).
 *
 * In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).
 *
 * Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption
 * works. Return a 500 if the MAC is invalid, and a 200 if it's OK.
 *
 * Using the timing leak in this application, write a program that discovers the valid MAC for any file.
 *
 * Why artificial delays?
 * Early-exit string compares are probably the most common source of cryptographic timing leaks, but they aren't
 * especially easy to exploit. In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably
 * aren't exploitable over a wide-area network at all. To play with attacking real-world timing leaks, you have to
 * start writing low-level timing code. We're keeping things cryptographic in these challenges.
 */
public class C31 {

    private final SHA1 sha1 = new SHA1();
    private final HMac hmac = new HMac(new SHA1Digest());

    /**
     * test that the HMAC function is, at bare minimum, deterministic.
     * there's no independent way to test
     */
    @Test
    void HMACisDeterministic() {
        final byte[] msg = "Chancellor on brink of second bailout for Banks".getBytes();
        final byte[] otherOut = new byte[hmac.getMacSize()];
        hmac.update(msg, 0, msg.length);
        hmac.doFinal(otherOut, 0);

        final var hmac1 = sha1.getHMAC(msg);
        assertArrayEquals(otherOut, hmac1);
    }

}
