package cryptopals.exceptions;

public class CryptopalsException extends RuntimeException {
    public CryptopalsException() {}
    public CryptopalsException(String message) {
        super(message);
    }
    public CryptopalsException(String message, Throwable t) {
        super(message, t);
    }
}
