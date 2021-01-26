package cryptopals.tool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cryptopals.exceptions.CryptopalsException;
import org.junit.jupiter.api.Test;

public class LittleEndianNonceTest {


    @Test
    void defaultNonceIsWhatIsExpected() {
        final LittleEndianNonce nonce = new LittleEndianNonce();
        assertArrayEquals(new byte[16], nonce.get());
    }

    @Test
    void singleIncrementYieldsIncrementInCorrectBlock() {
        final LittleEndianNonce nonce = new LittleEndianNonce();
        nonce.increment();
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, nonce.get());
    }

    @Test
    void fullIncrementCausesSpillOver() {
       final LittleEndianNonce nonce = new LittleEndianNonce(new byte[1], new byte[] {Byte.MAX_VALUE, 0});
       nonce.increment();
       assertArrayEquals(new byte[] {0, Byte.MAX_VALUE, 1}, nonce.get());
    }

    @Test
    void fullNonceThrowsException() {
        final LittleEndianNonce nonce = new LittleEndianNonce(new byte[1], new byte[] {Byte.MAX_VALUE, Byte.MAX_VALUE});
        assertThrows(CryptopalsException.class, nonce::increment);
    }

}
