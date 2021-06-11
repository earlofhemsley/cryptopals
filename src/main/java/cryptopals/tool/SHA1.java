package cryptopals.tool;

import com.google.common.base.Preconditions;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * a wrapping class for basic features of SHA-1
 */
public class SHA1 {

    /**
     * a private key that is different for every instance of the sha
     */
    private final byte[] privateKey = ByteArrayUtil.randomBytes(11);

    /**
     * given a key, a message and a mac, verify that the digest the comes from concatenating the key and the message
     * is equal to the submitted mac. Without knowing both they key and the message, you shouldn't be able to
     * authenticate the mac.
     * @param key a private key candidate
     * @param message a message
     * @param mac the mac to check
     * @return true if authenticated
     */
    public boolean authenticateMessage(final byte[] key, final String message, final String mac) {
        Preconditions.checkArgument(StringUtils.isNotBlank(message), "message cannot be blank");
        Preconditions.checkArgument(StringUtils.isNotBlank(mac), "mac cannot be blank");
        Preconditions.checkArgument(mac.length() == 40, "mac must be a 40-character string");

        return mac.equals(getMAC(key, message));
    }

    /**
     * given a message, generate a mac.
     * @param message the message
     * @return the mac
     */
    public String getMAC(String message) {
        return getMAC(privateKey, message);
    }

    /**
     * given a message and a key, generate a mac.
     *
     * @param key the key (usually the internal private key)
     * @param message the message
     * @return the mac
     */
    private String getMAC(final byte[] key, final String message) {
        final byte[] input = ByteArrayUtil.concatenate(key, message.getBytes(StandardCharsets.UTF_8));
        var d = new SHA1Digest();
        var out = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(out, 0);
        return Hex.toHexString(out);
    }
}
