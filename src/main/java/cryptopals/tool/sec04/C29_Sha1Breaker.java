package cryptopals.tool.sec04;

import cryptopals.tool.SHA1;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.util.Pack;

/**
 * a class dedicated to spoiling {@link cryptopals.tool.SHA1}
 */
@RequiredArgsConstructor
public class C29_Sha1Breaker extends AbstractBreaker {

    private final SHA1 sha1;

    /**
     * given a hash and a byte count, will override the state of the digest using reflection
     * @param hash the hash
     * @param byteCount the byte count
     */
    @Override
    protected void overrideState(final byte[] hash, final int byteCount) {
        //break the hash into 5 32-bit registers
        // the hash is a 40-char hex string, this is 20 bytes, which is 5 ints
        final int[] registers = new int[hash.length/4];
        assert registers.length >= 5;

        for (int i = 0; i < registers.length; i++) {
            registers[i] = Pack.bigEndianToInt(hash, i*4);
        }
        setPrivateField(sha1, "H1", registers[0], false);
        setPrivateField(sha1, "H2", registers[1], false);
        setPrivateField(sha1, "H3", registers[2], false);
        setPrivateField(sha1, "H4", registers[3], false);
        setPrivateField(sha1, "H5", registers[4], false);
        setPrivateField(sha1, "byteCount", byteCount, true);
    }

    @Override
    protected byte[] forceUpdate(byte[] appendix) {
        return forceUpdate(sha1, appendix);
    }

}
