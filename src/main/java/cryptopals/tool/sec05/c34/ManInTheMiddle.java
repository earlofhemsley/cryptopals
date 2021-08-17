package cryptopals.tool.sec05.c34;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.CBC;
import cryptopals.utils.ByteArrayUtil;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.math.BigInteger;

@Slf4j
@Setter
public class ManInTheMiddle extends NetworkRouter {

    private String expectedMessage;
    private final SHA1Digest sha1 = new SHA1Digest();

    @Override
    public BigInteger initDHKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey, String source, String destination) {
        if (!registry.containsKey(destination)) {
            throw new IllegalArgumentException(destination + " is not a known destination");
        }

        if(!registry.containsKey(source)) {
            throw new IllegalArgumentException(source + " is not a known network node");
        }

        final var dest = registry.get(destination);

        //man in the middle time
        // send the fake public key to the destination
        dest.receiveKeyExchangeRequest(g, p, source, p);

        // send the fake public key to the source as well
        return p;
    }

    @Override
    public byte[] routeMessage(byte[] message, String source, String destination) {
        if (!registry.containsKey(destination)) {
            throw new IllegalArgumentException(destination + " is not a known destination");
        }

        //if we did it right, the shared key is going to be ZERO, so use that to decrypt
        final var key = BigInteger.ZERO.toByteArray();
        final byte[] keyHash = new byte[sha1.getDigestSize()];
        sha1.update(key, 0, key.length);
        sha1.doFinal(keyHash, 0);

        final CBC cbc = new CBC(ByteArrayUtil.sliceByteArray(keyHash, 0, 16));
        final int cutpoint = message.length - 16;
        final byte[] iv = ByteArrayUtil.sliceByteArray(message, cutpoint, 16);
        final byte[] actualMsg = ByteArrayUtil.sliceByteArray(message, 0, cutpoint);
        final byte[] decrypted = cbc.decryptAsByteArray(actualMsg, iv);

        final var decryptedString = new String(decrypted);
        log.info("man in the middle slice! {}", decryptedString);

        if (!StringUtils.equals(decryptedString, this.expectedMessage)) {
            throw new CryptopalsException(String.format("Expected message '%s' did not match actual message '%s'",
                    this.expectedMessage, decryptedString));
        }

        final var dest = registry.get(destination);
        return dest.receiveEncryptedMessage(source, message);
    }
}
