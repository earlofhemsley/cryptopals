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

    private final byte[] privateKey = ByteArrayUtil.randomBytes(11);

    public boolean authenticateMessage(final byte[] key, final String message, final String mac) {
        Preconditions.checkArgument(StringUtils.isNotBlank(message), "message cannot be blank");
        Preconditions.checkArgument(StringUtils.isNotBlank(mac), "mac cannot be blank");
        Preconditions.checkArgument(mac.length() == 40, "mac must be a 40-character string");

        return mac.equals(getMAC(key, message));
    }

    public String getMAC(String message) {
        return getMAC(privateKey, message);
    }

    private String getMAC(final byte[] key, final String message) {
        final byte[] input = ByteArrayUtil.concatenate(key, message.getBytes(StandardCharsets.UTF_8));
        var d = new SHA1Digest();
        var out = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(out, 0);
        return Hex.toHexString(out);
    }
}
