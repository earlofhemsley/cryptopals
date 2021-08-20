package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.sec05.DiffieHellmanParty;
import cryptopals.tool.sec05.c34.GoodNetwork;
import cryptopals.tool.sec05.c34.ManInTheMiddle;
import cryptopals.tool.sec05.NetworkRouter;
import org.junit.jupiter.api.Test;

/**
 * Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
 * Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do
 * the network part of this if you don't want; just simulate that. The protocol is:
 *
 * A->B
 * Send "p", "g", "A"
 * B->A
 * Send "B"
 * A->B
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * B->A
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 * (In other words, derive an AES key from DH with SHA1, use it in both directions,
 * and do CBC with random IVs appended or prepended to the message).
 *
 * Now implement the following MITM attack:
 *
 * A->M
 * Send "p", "g", "A"
 * M->B
 * Send "p", "g", "p"
 * B->M
 * Send "B"
 * M->A
 * Send "p"
 * A->M
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * M->B
 * Relay that to B
 * B->M
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 * M->A
 * Relay that to A
 * M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire ---
 * have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.
 *
 * Decrypt the messages from M's vantage point as they go by.
 *
 * Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate
 * Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack.
 * But do the parameter injection attack; it's going to come up again.
 */
public class C34 {

    @Test
    void noManInTheMiddle() {
        final NetworkRouter router = new GoodNetwork();
        final var alice = new DiffieHellmanParty("alice", router);
        new DiffieHellmanParty("bob", router);

        alice.sendKeyExchangeRequest("bob");
        final boolean success = alice.sendEncryptedMessage("bob", "Inflation is a tax on savings");
        assertTrue(success, "the message sent appears to have been tampered with");
    }

    @Test
    void thereIsAManInTheMiddle() {
        final var mitm = new ManInTheMiddle();
        final String message = "Inflation is a tax on savings";
        mitm.setExpectedMessage(message);

        final var alice = new DiffieHellmanParty("alice", mitm);
        new DiffieHellmanParty("bob", mitm);

        alice.sendKeyExchangeRequest("bob");
        final boolean success = alice.sendEncryptedMessage("bob", message);
        assertTrue(success, "the message sent appears to have been tampered with");
    }
}
