package cryptopals.tool.sec05;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.CBC;
import cryptopals.utils.ByteArrayUtil;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.math.BigInteger;

@Slf4j
@Setter
public abstract class AbstractManInTheMiddle extends NetworkRouter {
    private final SHA1Digest sha1 = new SHA1Digest();
    private String expectedMessage;

    protected byte[] decrypt(final BigInteger sharedKey, final byte[] message, final byte[] iv) {
        final byte[] keyHash = getKeyHashFromKey(sharedKey);
        final CBC cbc = new CBC(ByteArrayUtil.sliceByteArray(keyHash, 0, 16));
        return cbc.decryptAsByteArray(message, iv);
    }

    protected byte[] encrypt(final BigInteger sharedKey, final byte[] plaintext, final byte[] iv) {
        final byte[] encSharedKeyHash = getKeyHashFromKey(sharedKey);
        final var cbc = new CBC(ByteArrayUtil.sliceByteArray(encSharedKeyHash, 0 , 16));
        final byte[] e = cbc.encryptToByteArray(plaintext, iv);
        return ByteArrayUtil.concatenate(e, iv);
    }

    protected void validateExpectedMessage(final String actualMessage) {
        log.info("man in the middle slice! {}", actualMessage);
        if (!StringUtils.equals(expectedMessage, this.expectedMessage)) {
            throw new CryptopalsException(String.format("Expected message '%s' did not match actual message '%s'",
                    this.expectedMessage, actualMessage));
        }
    }

    private byte[] getKeyHashFromKey(final BigInteger key) {
        final var keyArray = key.toByteArray();
        final byte[] keyHash = new byte[sha1.getDigestSize()];
        sha1.update(keyArray, 0, keyArray.length);
        sha1.doFinal(keyHash, 0);
        return ByteArrayUtil.sliceByteArray(keyHash, 0, 16);
    }


    protected Pair<byte[], byte[]> splitIntoMsgAndIv(byte[] message) {
        final int cutpoint = message.length - 16;
        final byte[] iv = ByteArrayUtil.sliceByteArray(message, cutpoint, 16);
        final byte[] actualMsg = ByteArrayUtil.sliceByteArray(message, 0, cutpoint);
        return Pair.of(actualMsg, iv);
    }
}
