package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.sec05.c34.GoodNetwork;
import cryptopals.tool.sec05.c36.SRPClient;
import cryptopals.tool.sec05.c36.SRPServer;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;

/**
 * Implement Secure Remote Password (SRP)
 * To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the
 * "opposite" operation an generate a numeric parameter from a hash. Then:
 *
 * Replace A and B with C and S (client & server)
 *
 * C & S
 *  - Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
 * S
 *  - Generate salt as random integer
 *  - Generate string xH=SHA256(salt|password)
 *  - Convert xH to integer x somehow (put 0x on hexdigest)
 *  - Generate v=g**x % N
 *  - Save everything but x, xH
 * C->S
 *  - Send I, A=g**a % N (a la Diffie Hellman)
 * S->C
 *  - Send salt, B=kv + g**b % N
 * S, C
 *  - Compute string uH = SHA256(A|B), u = integer of uH
 * C
 *  - Generate string xH=SHA256(salt|password)
 *  - Convert xH to integer x somehow (put 0x on hexdigest)
 *  - Generate S = (B - k * g**x)**(a + u * x) % N
 *  - Generate K = SHA256(S)
 * S
 *  - Generate S = (A * v**u) ** b % N
 *  - Generate K = SHA256(S)
 * C->S
 *  - Send HMAC-SHA256(K, salt)
 * S->C
 *  - Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * You're going to want to do this as a REPL of some sort; it may take a couple tries.
 *
 * It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256)
 * as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256,
 * and by converting the hexdigest to an integer when processing its output.
 *
 * This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The server also takes an
 * extra step to avoid storing an easily crackable password-equivalent.
 */
public class C36 {
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final BigInteger K = BigInteger.valueOf(3);
    private static final BigInteger N = new BigInteger(1, Hex.decode(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                    "fffffffffffff"
    ));

    @RepeatedTest(100)
    void theChallenge() throws DecoderException {
        final GoodNetwork network = new GoodNetwork();
        final SRPClient carol = new SRPClient("carol", network, G, K, N);
        final SRPServer steve = new SRPServer("steve", network, G, K, N);

        final String pw = "vaccine so effective you need a mask " +
                "mask so effective you need a vaccine";
        carol.register(carol.getName(), pw, steve.getName());
        final boolean successfulAuth = carol.authenticateSecurely(carol.getName(), pw, steve.getName());
        assertTrue(successfulAuth);
    }
}