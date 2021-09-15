package cryptopals.challenges.sec05;

import static cryptopals.CommonConstants.G;
import static cryptopals.CommonConstants.K;
import static cryptopals.CommonConstants.N;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.repl.InteractiveSrpLogin;
import cryptopals.tool.sec05.c34.GoodNetwork;
import cryptopals.tool.sec05.c36.SRPServer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Scanner;

/**
 * Break SRP with a zero key
 * Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.
 *
 * Now log in without your password by having the client send 0 as its "A" value. What does this do to the "S"
 * value that both sides compute?
 *
 * Now log in without your password by having the client send N, N*2, &c.
 *
 * Cryptanalytic MVP award
 * Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH are tricky to
 * "operationalize". But this attack uses the same concepts, and results in auth bypass. Almost every implementation of
 * SRP we've ever seen has this flaw; if you see a new one, go look for this bug.
 */
public class C37 {

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5})
    void login(final int multiple) {
        final String commands = "register\n" +
            "carol\n" +
            "asdf\n" +
            "execute order 66\n" +
            "carol\n" +
            String.format("%d\n", multiple) +
            "exit";

        final InputStream is = new ByteArrayInputStream(commands.getBytes());
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        final var server = new SRPServer("steve", new GoodNetwork(), G, K, N);
        final InteractiveSrpLogin console = new InteractiveSrpLogin(new Scanner(is), new PrintStream(os), server);

        assertDoesNotThrow(console::startConsole);
        assertTrue(os.toString().contains("Login successful. Welcome aboard"));
    }
}
