package cryptopals.tool;

import static com.google.common.base.Preconditions.checkArgument;

import cryptopals.utils.ByteArrayUtil;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.util.Arrays;

/**
 * a wrapping class for basic features of SHA-1, as implemented in the bouncycastle library
 * @see SHA1Digest
 */
public class SHA1 {

    /**
     * a private key that is different for every instance of the sha
     */
    private final byte[] privateKey = ByteArrayUtil.randomBytes(11);
    final SHA1Digest d = new SHA1Digest();

    /**
     * given a key, a message and a mac, verify that the digest the comes from concatenating the key and the message
     * is equal to the submitted mac. Without knowing both they key and the message, you shouldn't be able to
     * authenticate the mac.
     * @param message a message
     * @param mac the mac to check
     * @return true if authenticated
     */
    public boolean authenticateMessage(final byte[] message, final byte[] mac) {
        checkArgument(message.length > 0, "message length must be greater than 0");
        checkArgument(mac.length == 20, "mac must be a 20-element byte array");
        final byte[] freshMac = getMAC(message);
        return Arrays.equals(mac, freshMac);
    }

    /**
     * given a message, generate a mac.
     * @param message the message
     * @return the mac
     */
    public byte[] getMAC(byte[] message) {
        return getMAC(privateKey, message);
    }

    /**
     * given a message and a key, generate a mac.
     *
     * @param key the key (usually the internal private key)
     * @param message the message
     * @return the mac
     */
    private byte[] getMAC(final byte[] key, final byte[] message) {
        final byte[] input = ByteArrayUtil.concatenate(key, message);
        var out = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(out, 0);
        return out;
    }

}
