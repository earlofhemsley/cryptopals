package cryptopals.utils;

import lombok.experimental.UtilityClass;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;

@UtilityClass
public class HashUtil {

    /**
     * get a sha 256 hash of the input byte array
     * @param input the input byte array
     * @return the hash
     */
    public byte[] getSha256Hash(final byte[] input) {
        final SHA256Digest d = new SHA256Digest();
        final byte[] output = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(output, 0);
        return output;
    }

    /**
     * get a sha 256 hmac of the input byte array
     * @param input the input byte array
     * @return the hmac
     */
    public byte[] getSha256Hmac(final byte[] input) {
        final HMac hmac = new HMac(new SHA256Digest());
        final byte[] out = new byte[hmac.getMacSize()];
        hmac.update(input, 0, input.length);
        hmac.doFinal(out, 0);
        return out;
    }

    /**
     * simple util method to generate a hash, provided a digest
     * @param input the message to hash
     * @param d the digest to use
     * @return the hash
     */
    public byte[] getHash(final byte[] input, GeneralDigest d) {
        final byte[] output = new byte[d.getDigestSize()];
        d.update(input, 0, input.length);
        d.doFinal(output, 0);
        return output;
    }
}
