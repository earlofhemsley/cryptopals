package cryptopals.exceptions;

public class BadPaddingRuntimeException extends RuntimeException {
    public BadPaddingRuntimeException() {}
    public BadPaddingRuntimeException(String message) {
        super(message);
    }
    public BadPaddingRuntimeException(String message, Throwable t) {
        super(message, t);
    }
}
