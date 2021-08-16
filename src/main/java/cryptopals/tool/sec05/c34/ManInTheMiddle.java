package cryptopals.tool.sec05.c34;

import cryptopals.tool.CBC;
import cryptopals.tool.sec05.DiffieHellmanParty;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.math.BigInteger;

@Slf4j
public class ManInTheMiddle extends NetworkRouter {

    private final SHA1Digest sha1 = new SHA1Digest();

    @Override
    public BigInteger initDHKeyExchange(DiffieHellmanParty source, String destination) {
        if (!registry.containsKey(destination)) {
            throw new IllegalArgumentException(destination + " is not a known destination");
        }

        if(!registry.containsKey(source.getName())) {
            register(source);
        }

        final var dest = registry.get(destination);

        //man in the middle time
        // the source's p is the public key we are going to send to both parties
        final BigInteger zPublicKey = source.getP();

        // send the fake public key to the destination
        dest.receiveKeyExchangeRequest(source.getG(), source.getP(), source.getName(), zPublicKey);

        // send the fake public key to the source as well
        return zPublicKey;
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
        log.info("man in the middle slice! {}", new String(decrypted));

        final var dest = registry.get(destination);
        return dest.receiveEncryptedMessage(source, message);
    }
}
