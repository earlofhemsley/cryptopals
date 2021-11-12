package cryptopals.challenges.sec06;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.URI;

/**
 * Implement unpadded message recovery oracle
 * Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.
 *
 * Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages which
 * (again: Javascript) aren't padded before encryption at all.
 *
 * You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit the same message
 * twice: let's say the server keeps hashes of previous messages for some live-ness interval,
 * and that the message has an embedded timestamp:
 *
 * {
 *   time: 1356304276,
 *   social: '555-55-5555',
 * }
 *
 * You'd like to capture other people's messages and use the server to decrypt them. But when you try, the server takes
 * the hash of the ciphertext and uses it to reject the request. Any bit you flip in the ciphertext irrevocably
 * scrambles the decryption.
 *
 * This turns out to be trivially breakable:
 *
 * Capture the ciphertext C
 * Let N and E be the public modulus and exponent respectively
 * Let S be a random number > 1 mod N. Doesn't matter what.
 *
 * Now:
 * C' = ((S**E mod N) C) mod N
 * Submit C', which appears totally different from C, to the server, recovering P',
 * which appears totally different from P
 *
 * Now:
 *           P'
 *     P = -----  mod N
 *           S
 *
 * Oops!
 *
 * Implement that attack.
 *
 * Careful about division in cyclic groups.
 * Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N.
 * So you'll need an invmod() function.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class C41 {

    @Autowired
    private TestRestTemplate restTemplate;

    @LocalServerPort
    private int port;

    @Test
    void getBlobs() {
        final URI uri = URI.create(String.format("http://localhost:%d/rsa/blobs", port));
        ResponseEntity<String[]> response = restTemplate.getForEntity(uri, String[].class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotEquals(0, response.getBody().length);
    }
}
