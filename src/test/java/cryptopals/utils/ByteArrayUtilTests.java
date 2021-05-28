package cryptopals.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

public class ByteArrayUtilTests {

    @Test
    void testIntToByteArray() {
        assertArrayEquals(new byte[] {127, -1, -1, -1}, ByteArrayUtil.intToByteArray(Integer.MAX_VALUE));
        assertArrayEquals(new byte[] {-128, 0, 0, 0}, ByteArrayUtil.intToByteArray(Integer.MIN_VALUE));
        assertArrayEquals(new byte[] {-16, -16, -16, -16}, ByteArrayUtil.intToByteArray(-252645136));
    }
}
