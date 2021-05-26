package cryptopals.utils;

import lombok.experimental.UtilityClass;

@UtilityClass
public class BitMaskUtil {
    /**
     * take an int k, return a 32-bit mask filled with k bits of 1 from the right hand side
     * @param k how many bits to mask
     * @return the bitmask
     */
    public static int convertIntToRightEndMask(final int k) {
        int retval = 0;
        for (int i = k; i > 0; i--) {
            retval = retval << 1;
            retval = retval | 1;
        }
        return retval;
    }

    /**
     * take an int k, return a 32-bit mask filled with k bits of 1 from the left hand side
     * @param k how many bits to mask
     * @return the bitmask
     */
    public static int convertIntToLeftEndMask(final int k) {
        int retval = 0;
        for (int i = k; i > 0; i--) {
            retval = retval >>> 1;
            retval = retval | 0x80000000;
        }
        return retval;
    }
}
