package cryptopals.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.IntStream;

@UtilityClass
@Slf4j
public class CharacterUtil {

    private static final char[] ALPHANUMERICS = new char[62];
    static {
        IntStream U = IntStream.range('A', 'Z' + 1);
        IntStream l = IntStream.range('a', 'z' + 1);
        IntStream n = IntStream.range('0', '9' + 1);
        final var temp = IntStream.concat(U, IntStream.concat(l, n)).toArray();
        for (int i = 0; i < ALPHANUMERICS.length; i++) {
            ALPHANUMERICS[i] = (char) temp[i];
        }
    }
    /**
     * take any byte and convert it into an english alphanumeric character (0-9 or A-Z or a-z)
     * @param s the byte
     * @return the character
     */
    public char byteToAlphaNumericCharacter(final byte s) {
        final int index = Math.abs((int) s % ALPHANUMERICS.length);
        return ALPHANUMERICS[index];
    }
}
