package cryptopals.tool.sec04;

import cryptopals.tool.MD4;
import lombok.RequiredArgsConstructor;

/**
 * a class dedicated to spoiling {@link cryptopals.tool.MD4}
 */
@RequiredArgsConstructor
public class C30_MD4Breaker extends AbstractBreaker {

    private final MD4 md4;

    /**
     * md4 does this little endian style
     * @param block the block to pack
     * @param messageBitCount the bit count
     */
    @Override
    protected void packTheBitCount(byte[] block, long messageBitCount) {
        final int startPos = block.length - 1 - BIT_COUNT_SPACE;

        for (int i = startPos; i < block.length; i++) {
            block[i] = (byte) (messageBitCount >>> (i*8));
        }
    }

    @Override
    protected void overrideState(byte[] previousHash, int newByteCount) {
        //break the hash into 5 32-bit registers
        // the hash is a 32-char hex string, this is 16 bytes, which is 4 ints
        final int[] registers = new int[previousHash.length/4];
        assert registers.length >= 4;

        for (int i = 0; i < registers.length; i++) {
            registers[i] = packWord(previousHash, i*4);
        }

        setPrivateField(md4, "H1", registers[0], false);
        setPrivateField(md4, "H2", registers[1], false);
        setPrivateField(md4, "H3", registers[2], false);
        setPrivateField(md4, "H4", registers[3], false);

        setPrivateField(md4, "byteCount", newByteCount, true);
    }

    private int packWord(final byte[] hash, final int hashOffset) {
        int word = 0;
        for (int o = 0; o < 4; o++) {
            word |= (hash[hashOffset + o] & 0xff) << (o * 8);
        }
        return word;
    }

    @Override
    protected byte[] forceUpdate(byte[] appendix) {
        return forceUpdate(md4, appendix);
    }

}
