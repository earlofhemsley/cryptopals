package cryptopals.exceptions;

import lombok.Getter;
import lombok.Setter;

/**
 * This class is intended to be thrown if a message contains what is deemed ot be
 * an invalid character.
 */
@Getter
@Setter
public class InvalidPlaintextByteException extends RuntimeException {

    /**
     * it's super insecure to make the original message accessible,
     * but that's sort of the point of the exercise, so I'm rolling with it
     */
    private byte[] plainTextBytes;

    public InvalidPlaintextByteException(String message, byte[] plainTextBytes) {
        super(message);
        this.plainTextBytes = plainTextBytes;
    }

    private static final byte LOWER_BOUND = ' ';
    private static final byte UPPER_BOUND = '~';
    public static void throwIfContainsInvalidCharacter(byte[] subject) {
        for (byte c : subject) {
            if (c < LOWER_BOUND || c > UPPER_BOUND) {
                throw new InvalidPlaintextByteException(String.format("%s contains an invalid character: %s",
                        new String(subject), c), subject);
            }
        }
    }
}
