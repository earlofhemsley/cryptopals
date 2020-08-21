package cryptopals.utils;

import cryptopals.exceptions.BadPaddingRuntimeException;

import java.util.Arrays;

/**
 * a tool to apply or strip padding from a plain text
 */
public class PKCS7Util {

    private PKCS7Util() {
        throw new AssertionError("Cannot instantiate PCKS7Util");
    }

    /**
     * given a message and a block size, implement pkcs7 padding on the message to make the message conform to the block size
     *
     * this is the solution to challenge nine
     * @param messageBytes
     * @param blockSize
     * @return
     */
    public static byte[] applyPadding(byte[] messageBytes, int blockSize) {
        if (blockSize >= 256 || blockSize <= 0) {
            throw new IllegalArgumentException("Block size can only be between 1 and 255, inclusive");
        }
        int numOfPaddingBytes = blockSize - messageBytes.length % blockSize;

        int newLength = (int) Math.ceil((double) messageBytes.length / blockSize) * blockSize;
        if (newLength == messageBytes.length) {
            newLength += blockSize;
        }

        byte[] paddedMessage = Arrays.copyOf(messageBytes, newLength);

        for (int i = messageBytes.length; i<messageBytes.length + numOfPaddingBytes; i++) {
            paddedMessage[i] = (byte) numOfPaddingBytes;
        }

        return paddedMessage;
    }

    /**
     * Strip padding if possible
     * @param plainText
     * @return
     */
    public static byte[] stripPadding(byte[] plainText) {
        int last = plainText[plainText.length - 1];
        if (plainText.length - last < 0 || plainText.length - last >= plainText.length) {
            throw new BadPaddingRuntimeException("padding bytes result in indices outside the length of the plain text");
        }
        for (int i = last; i > 0; i--) {
            if (plainText[plainText.length - last] != last) {
                throw new BadPaddingRuntimeException("last n bytes of block didn't match");
            }
        }
        int toKeep = plainText.length - last;
        return Utils.sliceByteArray(plainText, 0, toKeep);
    }
}
