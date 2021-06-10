package cryptopals.exceptions;

import java.util.Arrays;
import java.util.Base64;

/**
 * This class is intended to be thrown if a message contains what is deemed ot be
 * an invalid character.
 */
public class InvalidPlaintextByteException extends RuntimeException {

    public InvalidPlaintextByteException(String message) {
        super(message);
    }

    private static final byte LOWER_BOUND = ' ';
    private static final byte UPPER_BOUND = '~';

    /**
     * if an invalid byte shows up in a subject, then stringify that subject and throw an exception
     *
     * normally I would use new String(subject), but java doesn't preserve message bytes as part of String::new,
     * encoding to base 64 was a good way to retain the byte values without just offering the bytes themselves,
     * and it's not immediately obvious that it is a base 64 string anyway
     *
     * @param subject plaintext byte array
     */
    public static void throwIfContainsInvalidCharacter(byte[] subject) {
        for (byte c : subject) {
            if (c < LOWER_BOUND || c > UPPER_BOUND) {
                throw new InvalidPlaintextByteException(String.format("%s contains an invalid character: %s",
                        Base64.getEncoder().encodeToString(subject), c));
            }
        }
    }
}
