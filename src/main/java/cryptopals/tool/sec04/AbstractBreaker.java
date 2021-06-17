package cryptopals.tool.sec04;

import cryptopals.utils.ByteArrayUtil;
import lombok.SneakyThrows;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public abstract class AbstractBreaker {
    private static final int BLOCK_SIZE = 64;
    private static final int BIT_COUNT_SPACE = 8;

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
    public byte[] buildGluePadding(final byte[] message) {
        //build a 512-bit block
        byte[] block = new byte[BLOCK_SIZE];

        //get the last 64 characters of the message
        //or if it IS 64, then an empty byte array
        final byte[] subMsg;
        if (message.length == BLOCK_SIZE) {
            subMsg = new byte[0];
        } else if (message.length > BLOCK_SIZE) {
            final int startPos = (message.length / 64) * 64;
            subMsg = new byte[message.length - startPos];
            System.arraycopy(message, startPos, subMsg, 0, message.length - startPos);
        } else {
            subMsg = message;
        }

        //copy the message bytes into the block
        System.arraycopy(subMsg, 0, block, 0, subMsg.length);
        int index = subMsg.length;

        //make the next byte the flag byte
        block[index++] = Byte.MIN_VALUE;

        //have to allow for the bit count to take up to 8 bytes
        if (index >= BLOCK_SIZE - BIT_COUNT_SPACE) {
            block = ByteArrayUtil.concatenate(block, new byte[BLOCK_SIZE]);
        }

        //get the number of bits in the message
        final long messageBitLength = (long) message.length << 3;
        for (int i = 0; i < BIT_COUNT_SPACE; i++) {
            block[block.length - 1 - i] = (byte) (messageBitLength >>> (i*8));
        }

        final int padLength = block.length - subMsg.length;
        final byte[] returnValue = new byte[padLength];
        System.arraycopy(block, subMsg.length, returnValue, 0, padLength);

        return returnValue;
    }

    /**
     * given a hash, a byte count, and a new message meant to be appended to the message that resulted in
     * the hash, force override the state of the sha1 digest and get the new hash for the message with the
     * appendix appended to that message
     * @param previousHash the hash from the previous message
     * @param newByteCount the byte count wrapped into the hash
     * @param appendix what to append to the message that resulted in the previous hash
     * @return the new hash
     */
    public byte[] breakIt(final byte[] previousHash, final int newByteCount, final byte[] appendix) {
        overrideState(previousHash, newByteCount);
        return forceUpdate(appendix);
    }

    protected abstract void overrideState(final byte[] previousHash, final int newByteCount);

    protected abstract byte[] forceUpdate(final byte[] appendix);

    @SneakyThrows
    protected static void setPrivateField(final Object target, final String fieldName, final Object value, final boolean isSuperClassField) {
        final Field digestField = target.getClass().getDeclaredField("d");
        digestField.setAccessible(true);
        final Object d = digestField.get(target);
        final Class<?> subjectClass = isSuperClassField ? d.getClass().getSuperclass() : d.getClass();
        final Field f = subjectClass.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(d, value);
    }

    @SneakyThrows
    protected static byte[] forceUpdate(final Object target, final byte[] message) {
        final Method m = target.getClass().getSuperclass()
                .getDeclaredMethod("getMAC", byte[].class, byte[].class);
        m.setAccessible(true);
        return (byte[]) m.invoke(target, new byte[0], message);
    }
}
