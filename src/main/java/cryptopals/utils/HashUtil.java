package cryptopals.utils;

import lombok.experimental.UtilityClass;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;

@UtilityClass
public class HashUtil {

    public byte[] getSha256Hash(final byte[] input) {
        final SHA256Digest d = new SHA256Digest();
        final byte[] output = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(output, 0);
        return output;
    }

    public byte[] getSha256Hmac(final byte[] input) {
        final HMac hmac = new HMac(new SHA256Digest());
        final byte[] out = new byte[hmac.getMacSize()];
        hmac.update(input, 0, input.length);
        hmac.doFinal(out, 0);
        return out;
    }
}
