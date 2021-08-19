package cryptopals.tool.sec05.c34;

import cryptopals.tool.sec05.AbstractManInTheMiddle;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;

/**
 * this man in the middle router forwards p on as the shared key to both parties
 */
@Slf4j
@Setter
public class ManInTheMiddle extends AbstractManInTheMiddle {

    private String expectedMessage;

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
        validatePartyRegistry(destination);

        //if we did it right, the shared key is going to be ZERO, so use that to decrypt
        final var msgAndIv = splitIntoMsgAndIv(message);
        final byte[] decrypted = decrypt(BigInteger.ZERO, msgAndIv.getLeft(), msgAndIv.getRight());

        validateExpectedMessage(new String(decrypted));

        final var dest = registry.get(destination);
        return dest.receiveEncryptedMessage(source, message);
    }
}
