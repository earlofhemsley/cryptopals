package cryptopals.exceptions;

import java.util.Arrays;

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
     * Arrays::toString was a compromise to retain the byte values without just offering the bytes themselves
     *
     * @param subject plaintext byte array
     */
    public static void throwIfContainsInvalidCharacter(byte[] subject) {
        for (byte c : subject) {
            if (c < LOWER_BOUND || c > UPPER_BOUND) {
                throw new InvalidPlaintextByteException(String.format("%s contains an invalid character: %s",
                        Arrays.toString(subject), c));
            }
        }
    }
}
