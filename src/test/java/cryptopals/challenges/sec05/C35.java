package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import cryptopals.tool.sec05.DiffieHellmanParty;
import cryptopals.tool.sec05.c35.ManInTheMiddle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;

import java.math.BigInteger;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Implement DH with negotiated groups, and break with malicious "g" parameters
 *
 * A->B
 * Send "p", "g"
 *
 * B->A
 * Send ACK
 *
 * A->B
 * Send "A"
 *
 * B->A
 * Send "B"
 *
 * A->B
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 *
 * B->A
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *
 * Do the MITM attack again, but play with "g". What happens with:
 *     g = 1
 *     g = p
 *     g = p - 1
 *
 * Write attacks for each.
 *
 * When does this ever happen?
 * Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with
 * something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve
 * Diffie-Hellman, and this becomes more relevant there.
 */
public class C35 {

    @ParameterizedTest
    @MethodSource("supplyManipulatingCallbacks")
    @NullSource
    void thereIsANewManInTheMiddle(Function<BigInteger, BigInteger> callback) {
        final var mitm = new ManInTheMiddle();
        final String message = "Afghanistan is where empires go to die";
        mitm.setExpectedMessage(message);
        mitm.setGCallback(callback);

        final var alice = new DiffieHellmanParty("alice", mitm);
        new DiffieHellmanParty("bob", mitm);

        alice.sendKeyExchangeRequest("bob");
        final boolean success = alice.sendEncryptedMessage("bob", message);
        assertTrue(success, "the message sent appears to have been tampered with");
    }

    static Stream<Arguments> supplyManipulatingCallbacks() {
        return Stream.of(
                arguments((Function<BigInteger, BigInteger>) (p) -> BigInteger.ONE),
                arguments((Function<BigInteger, BigInteger>) (p) -> p),
                arguments((Function<BigInteger, BigInteger>) (p) -> p.subtract(BigInteger.ONE))
        );
    }
}
