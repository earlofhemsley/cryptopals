package cryptopals.challenges;

import java.util.Arrays;

public class Section02 {
    /**
     * given a message and a block size, implement pkcs7 padding on the message to make the message conform to the block size
     *
     * this is the solution to challenge nine
     *
     * @param messageBytes
     * @param blockSize
     * @return
     */
    public static byte[] implementPKCS7Padding(byte[] messageBytes, int blockSize) {
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
}
