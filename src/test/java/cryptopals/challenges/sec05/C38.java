package cryptopals.challenges.sec05;

import static cryptopals.CommonConstants.G;
import static cryptopals.CommonConstants.N;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.tool.sec05.c34.GoodNetwork;
import cryptopals.tool.sec05.c38.SimplifiedSRPClient;
import cryptopals.tool.sec05.c38.SimplifiedSRPServer;
import org.junit.jupiter.api.Test;

/**
 * Offline dictionary attack on simplified SRP
 *
 * Server
 * x = SHA256(salt|password)
 *     v = g**x % n
 *
 * C->S
 * I, A = g**a % n
 *
 * S->C
 * salt, B = g**b % n, u = 128 bit random number
 *
 * Client
 * x = SHA256(salt|password)
 *     S = B**(a + ux) % n
 *     K = SHA256(S)
 *
 *     S = (g**b % n)**(a + ux) % n
 *
 * Server
 * S = (A * v ** u)**b % n
 *      ((g**a % n) * (g**x % n)**u)**b % n
 *      ((g**a % n) * (g**ux % n)**b % n
 *      (g**(a + ux) % n)**b % n
 *      (g**b % n)**(a + ux) % n
 *     K = SHA256(S)
 *
 * C->S Send HMAC-SHA256(K, salt)
 *
 * S->C Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).
 *
 * Make sure the protocol works given a valid password.
 *
 * Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.
 *
 * Crack the password from A's HMAC-SHA256(K, salt).
 */
public class C38 {

    @Test
    void worksWithValidPassword() {
        final NetworkRouter n = new GoodNetwork();
        final SimplifiedSRPClient client = new SimplifiedSRPClient("client", n, G, N);
        final SimplifiedSRPServer server = new SimplifiedSRPServer("server", n, G, N);

        final String username = "claire";
        final String password = "cryptopals";
        client.register(username, password, server.getName());

        assertTrue(client.authenticate(username, password, server.getName()));
    }
}
