package cryptopals.exceptions;

public class BadPaddingRuntimeException extends RuntimeException {
    public BadPaddingRuntimeException(String message) {
        super(message);
    }
}
