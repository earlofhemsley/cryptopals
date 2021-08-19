package cryptopals.tool.sec05.c35;

import cryptopals.tool.sec05.AbstractManInTheMiddle;
import lombok.Setter;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * this man in the middle router manipulates g
 * and administers the attack in a more common way
 */
@Setter
public class ManInTheMiddle extends AbstractManInTheMiddle {
    private BigInteger forcedG;

    private final BigInteger myPrivateKey = BigInteger.valueOf(Math.abs(new Random(System.currentTimeMillis()).nextInt()));
    final Map<String, BigInteger> sharedKeyMap = new HashMap<>();

    private BigInteger createSharedKey(final BigInteger otherPublicKey, final BigInteger p) {
        return otherPublicKey.modPow(myPrivateKey, p);
    }

    private BigInteger createPublicKey(final BigInteger g, final BigInteger p) {
        return g.modPow(myPrivateKey, p);
    }

    @Override
    public BigInteger initDHKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey,
                                        String source, String destination) {
        validatePartyRegistry(destination);
        validatePartyRegistry(source);

        final var dest = registry.get(destination);

        //part of this challenge is to toy with G
        final BigInteger destG = forcedG == null ? g : forcedG;

        //man in the middle time
        // send my own parameters to the destination,
        // and use the public key that I get back to create a shared key with that party
        final var publicKeyForD = createPublicKey(destG, p);
        final var publicKeyOfD = dest.receiveKeyExchangeRequest(destG, p, source, publicKeyForD);
        sharedKeyMap.put(destination, createSharedKey(publicKeyOfD, p));

        //now for the source
        // they gave me their public key, so I can just derive a shared key with them
        final BigInteger sourceSharedKey = createSharedKey(sourcePublicKey, p);
        sharedKeyMap.put(source, sourceSharedKey);

        //return a public key to the source
        return createPublicKey(g, p);
    }

    @Override
    public byte[] routeMessage(byte[] message, String source, String destination) {
        final var sMsgIv = splitIntoMsgAndIv(message);

        //decrypt the message coming from source
        validatePartyRegistry(source);
        final var sSharedKey = sharedKeyMap.get(source);
        final byte[] sDecrypted = decrypt(sSharedKey, sMsgIv.getLeft(), sMsgIv.getRight());
        validateExpectedMessage(new String(sDecrypted));

        //re-encrypt for destination
        validatePartyRegistry(destination);
        final var dSharedKey = sharedKeyMap.get(destination);
        final byte[] reEncrypted = encrypt(dSharedKey, sDecrypted, sMsgIv.getRight());

        //send to destination and get response
        final var d = registry.get(destination);
        final var response = d.receiveEncryptedMessage(source, reEncrypted);

        //do the same in reverse
        final var dMsgIv = splitIntoMsgAndIv(response);
        final byte[] dDecrypted = decrypt(dSharedKey, dMsgIv.getLeft(), dMsgIv.getRight());
        validateExpectedMessage(new String(dDecrypted));

        return encrypt(sSharedKey, dDecrypted, dMsgIv.getRight());
    }
}
