package cryptopals.tool;

import cryptopals.utils.ByteArrayUtil;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * a wrapping class for basic features of SHA-1, as implemented in the bouncycastle library
 * @see SHA1Digest
 */
public class SHA1 extends AbstractDigestWrapper<SHA1Digest> {
    private final SHA1Digest d = new SHA1Digest();

    @Override
    protected SHA1Digest getDigest() {
        return d;
    }

    @Override
    protected int getBlockSize() {
        return 64;
    }
}
