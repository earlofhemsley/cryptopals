package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.fail;

import cryptopals.tool.SHA1;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.Field;
import java.net.URI;

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
@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class C31 {

    private final SHA1 sha1 = new SHA1();
    private final HMac hmac = new HMac(new SHA1Digest());

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * the best way to verify that the way that _I_ implemented the HMAC
     * is correct is to verify it it against an independent source.
     *
     * Since we've got the bouncycastle library, might as well use it as guard rails
     *
     * assert that there is no difference between a bouncy castle HMAC and the one I implemented
     * with my little SHA1 class
     */
    @Test
    void HMACisDeterministic() {
        final byte[] msg = "Chancellor on brink of second bailout for Banks".getBytes();
        final byte[] bcHMAC = new byte[hmac.getMacSize()];
        final var pk = extractPrivateKey(sha1);
        final var kp = new KeyParameter(pk);
        hmac.init(kp);
        hmac.update(msg, 0, msg.length);
        hmac.doFinal(bcHMAC, 0);
        assertArrayEquals(bcHMAC, sha1.getHMAC(msg));
    }

    @SneakyThrows
    private byte[] extractPrivateKey(final Object target) {
        final Field f = target.getClass().getSuperclass().getDeclaredField("privateKey");
        f.setAccessible(true);
        return (byte[]) f.get(target);
    }

    /**
     * verify that garbage in gives us garbage out
     */
    @ParameterizedTest
    @ValueSource(strings = {"", "xyz", "b4ec586117154dacd4"})
    void badRequests(final String signature) {
        final URI uri = URI.create(String.format("http://localhost:%s/c31/test/%s?signature=%s",
                port,
                "foo",
                signature
                ));
        final ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Bad Request", response.getBody());
    }

    /**
     * the key to this is that you can time request response to verify that
     * you've made progress. Once you know what a byte is, you don't have to check it again
     * this reduces the complexity of the attack to 256*20.
     */
    @Test
    void completeTheChallenge() {

        //start with all zeros
        byte[] forgedHash = new byte[20];

        //make a request to wake the server up
        makeRequest(forgedHash);

        //define a threshold. if a request takes longer than this, count it as valid
        long threshold = 25L;
        long responseTime;
        boolean found;

        for (int i = 0; i < forgedHash.length; i++) {
            int j = Byte.MIN_VALUE;
            do {
                forgedHash[i] = (byte) j;
                final long startTime = System.currentTimeMillis();
                makeRequest(forgedHash);
                responseTime = System.currentTimeMillis() - startTime;
                j++;
                found = responseTime > threshold;
            } while (!found && j <= Byte.MAX_VALUE);

            if (!found) {
                fail(String.format("failed to detect the byte using timing leak. result before failure: %s",
                        Hex.toHexString(forgedHash)));
            }

            log.info("found a byte. now the hash is {}", Hex.toHexString(forgedHash));

            //add fifty to the threshold
            threshold += 50;
        }
        log.info("the hash was {}", Hex.toHexString(forgedHash));
        assertEquals(HttpStatus.OK, makeRequest(forgedHash));
    }

    private HttpStatus makeRequest(final byte[] forgedHash) {
        final String file = "bucko";
        final String signature = Hex.toHexString(forgedHash);
        final URI uri = URI.create(String.format("http://localhost:%s/c31/test/%s?signature=%s",
                port,
                file,
                signature
        ));
        final ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
        assertNotEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        return response.getStatusCode();
    }

}
