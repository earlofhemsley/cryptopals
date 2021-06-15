package cryptopals.tool.sec04;

import cryptopals.tool.SHA1;
import cryptopals.utils.ByteArrayUtil;
import lombok.RequiredArgsConstructor;

import java.nio.charset.StandardCharsets;

/**
 * a class dedicated to spoiling {@link cryptopals.tool.SHA1}
 */
@RequiredArgsConstructor
public class C29_Sha1Breaker {
    private static final int BLOCK_SIZE = 64;
    private static final int BIT_COUNT_SPACE = 8;

    private final SHA1 sha1;

    /**
     * given a message, build the MD padding as close to the same
     * way as possible
     *
     * the algorithm, best as i can tell, leads with a single bit and then over-writes
     * the last byte of the 512-bit block with the number of BITS in the message
     *
     * @param message the message
     * @return the md padding
     */
    public byte[] buildMDPadding(final String message) {
        //build a 512-bit block
        byte[] block = new byte[BLOCK_SIZE];

        //get the last 64 characters of the message
        //or if it IS 64, then an empty byte array
        final String subMsg;
        if (message.length() == BLOCK_SIZE) {
            subMsg = "";
        } else if (message.length() > BLOCK_SIZE) {
            final int startPos = (message.length() / 64) * 64;
            subMsg = message.substring(startPos);
        } else {
            subMsg = message;
        }

        //copy the message bytes into the block
        final byte[] bytes = subMsg.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, block, 0, bytes.length);
        int index = bytes.length;

        //make the next byte the flag byte
        block[index++] = Byte.MIN_VALUE;

        //have to allow for the bit count to take up to 8 bytes
        if (index >= BLOCK_SIZE - BIT_COUNT_SPACE) {
            block = ByteArrayUtil.concatenate(block, new byte[BLOCK_SIZE]);
        }

        //get the number of bits in the message
        final long messageBitLength = (long) message.length() << 3;
        for (int i = 0; i < BIT_COUNT_SPACE; i++) {
            block[block.length - 1 - i] = (byte) (messageBitLength >>> (i*8));
        }

        final int padLength = block.length - bytes.length;
        final byte[] returnValue = new byte[padLength];
        System.arraycopy(block, bytes.length, returnValue, 0, padLength);
        return returnValue;
    }
}
