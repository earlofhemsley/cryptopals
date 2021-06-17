package cryptopals.tool.sec04;

import cryptopals.tool.SHA1;
import cryptopals.utils.ByteArrayUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.Pack;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

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
    public byte[] buildMDPadding(final byte[] message) {
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
    public byte[] crackTheSha(final byte[] previousHash, final int newByteCount, final byte[] appendix) {
        overrideState(previousHash, newByteCount);
        return forceUpdate(appendix);
    }

    /**
     * given a hash and a byte count, will override the state of the digest using reflection
     * @param hash the hash
     * @param byteCount the byte count
     */
    private void overrideState(final byte[] hash, final int byteCount) {
        //break the hash into 5 32-bit registers
        // the hash is a 40-char hex string, this is 20 bytes, which is 5 ints
        final int[] registers = new int[hash.length/4];
        assert registers.length >= 5;

        for (int i = 0; i < registers.length; i++) {
            registers[i] = Pack.bigEndianToInt(hash, i*4);
        }
        setSha1PrivateField("H1", registers[0], false);
        setSha1PrivateField("H2", registers[1], false);
        setSha1PrivateField("H3", registers[2], false);
        setSha1PrivateField("H4", registers[3], false);
        setSha1PrivateField("H5", registers[4], false);
        setSha1PrivateField("byteCount", byteCount, true);
    }

    @SneakyThrows
    private byte[] forceUpdate(final byte[] message) {
        final Method m = sha1.getClass().getDeclaredMethod("getMAC", byte[].class, byte[].class);
        m.setAccessible(true);
        return (byte[]) m.invoke(sha1, new byte[0], message);
    }

    @SneakyThrows
    private void setSha1PrivateField(final String fieldName, final Object value, final boolean isSuperClassField) {
        final Field digestField = sha1.getClass().getDeclaredField("d");
        digestField.setAccessible(true);
        final SHA1Digest d = (SHA1Digest) digestField.get(sha1);
        final Class<?> subjectClass = isSuperClassField ? d.getClass().getSuperclass() : d.getClass();
        final Field f = subjectClass.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(d, value);
    }
}
