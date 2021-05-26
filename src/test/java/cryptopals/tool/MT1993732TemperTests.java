package cryptopals.tool;

import static cryptopals.tool.MT19937_32.Temper;
import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.utils.BitMaskUtil;
import org.junit.jupiter.api.Test;

/**
 * test each method in the untemper class
 * each of these steps is in {@link MT19937_32}
 */
public class MT1993732TemperTests {

    private final int start = -416215821;
    private final Temper t = new Temper();

    @Test
    void testUndoStepOne() {
        int y = t.first(start);
        int finish = t.undoFirst(y);
        assertEquals(start, finish);
    }

    @Test
    void testUndoStepTwo() {
        int y = t.second(start);
        int finish = t.undoSecond(y);
        assertEquals(start, finish);
    }

    @Test
    void testUndoStepThree() {
        int y = t.third(start);
        int finish = t.undoThird(y);
        assertEquals(start, finish);
    }

    @Test
    void testUndoStepFour() {
        int y = t.fourth(start);
        int finish = t.undoFourth(y);
        assertEquals(start, finish);
    }

    @Test
    void convertIntToLowMask() {
        assertEquals(0x0000007F, BitMaskUtil.convertIntToRightEndMask(7));
    }

    @Test
    void convertIntToHighMask() {
        assertEquals(0xFFE00000, BitMaskUtil.convertIntToLeftEndMask(11));
    }

}
