package cryptopals.tool.sec04;

import cryptopals.tool.MD4;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.util.Pack;

/**
 * a class dedicated to spoiling {@link cryptopals.tool.MD4}
 */
@RequiredArgsConstructor
public class C30_MD4Breaker extends AbstractBreaker {

    private final MD4 md4;

    @Override
    protected void overrideState(byte[] previousHash, int newByteCount) {
        //break the hash into 5 32-bit registers
        // the hash is a 32-char hex string, this is 16 bytes, which is 4 ints
        final int[] registers = new int[previousHash.length/4];
        assert registers.length >= 4;

        for (int i = 0; i < registers.length; i++) {
            registers[i] = Pack.bigEndianToInt(previousHash, i*4);
        }

        setPrivateField(md4, "H1", registers[0], false);
        setPrivateField(md4, "H2", registers[1], false);
        setPrivateField(md4, "H3", registers[2], false);
        setPrivateField(md4, "H4", registers[3], false);

        setPrivateField(md4, "byteCount", newByteCount, true);
    }

    @Override
    protected byte[] forceUpdate(byte[] appendix) {
        return forceUpdate(md4, appendix);
    }

}
