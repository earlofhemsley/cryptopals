package cryptopals.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class BitMaskUtilTests {
    @Test
    void convertIntToLowMask() {
        assertEquals(0x0000007F, BitMaskUtil.convertIntToRightEndMask(7));
    }

    @Test
    void convertIntToHighMask() {
        assertEquals(0xFFE00000, BitMaskUtil.convertIntToLeftEndMask(11));
    }
}
