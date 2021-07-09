package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.sec04.C31_32_TimingLeakExploiter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.util.concurrent.ExecutionException;

/**
 * Break HMAC-SHA1 with a slightly less artificial timing leak
 * Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)
 *
 * Now break it again.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "leaking.delay=5")
public class C32 {
    private static final String FILE = "FAHayek";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * this is the same challenge as 31, but with a shorter leaking delay
     */
    @Test
    void completeTheChallenge() throws ExecutionException, InterruptedException {
        final C31_32_TimingLeakExploiter exploiter = new C31_32_TimingLeakExploiter(FILE, port, restTemplate.getRestTemplate(), 5);

        //start with a cheat set
        byte[] forgedHash = getCheatBytes();

        //define a threshold. if a request takes longer than this, count it as valid
        exploiter.exploitLeak(forgedHash);

        assertEquals(HttpStatus.OK, exploiter.makeRequest(forgedHash).get().getKey());
    }

    private byte[] getCheatBytes() {
        final URI uri = URI.create(String.format("http://localhost:%s/leak/cheat/%s/%d",
                port,
                FILE,
                8
        ));
        final var hexCheat = restTemplate.getForObject(uri, String.class);
        return Hex.decode(hexCheat);
    }
}
