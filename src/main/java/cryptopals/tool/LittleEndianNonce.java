package cryptopals.tool;

import cryptopals.exceptions.CryptopalsException;

/**
 * this class is intended to emulate little-endian behavior for an incremental nonce
 */
public class LittleEndianNonce {
    private static final int DEFAULT_BLOCK_LENGTH = 8;

    private final byte[] nonce;
    private int incrementalPosition;

    public LittleEndianNonce() {
        this(new byte[DEFAULT_BLOCK_LENGTH], new byte[DEFAULT_BLOCK_LENGTH]);
    }

    public LittleEndianNonce(byte[] noncePrefix, byte[] incrementalBlock) {
        this.incrementalPosition = noncePrefix.length;
        this.nonce = new byte[noncePrefix.length + incrementalBlock.length];
        System.arraycopy(noncePrefix, 0, nonce, 0, noncePrefix.length);
        System.arraycopy(incrementalBlock, 0, this.nonce, this.incrementalPosition, incrementalBlock.length);
    }

    public void increment() {
        while (incrementalPosition < nonce.length && nonce[incrementalPosition] == Byte.MAX_VALUE) {
            incrementalPosition++;
        }

        if (incrementalPosition >= nonce.length) {
            throw new CryptopalsException("Nonce is full. Cannot increment");
        }

        nonce[incrementalPosition]++;
    }

    public byte[] get() {
        return this.nonce;
    }

}
