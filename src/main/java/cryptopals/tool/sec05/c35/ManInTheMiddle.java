package cryptopals.tool.sec05.c35;

import cryptopals.tool.sec05.AbstractManInTheMiddle;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * this man in the middle router manipulates g
 * and administers the attack in a more common way
 */
@Slf4j
@Setter
public class ManInTheMiddle extends AbstractManInTheMiddle {
    private Function<BigInteger, BigInteger> gCallback;

    private final BigInteger myPrivateKey = BigInteger.valueOf(Math.abs(new Random(System.currentTimeMillis()).nextInt()));
    final Map<String, BigInteger> sharedKeyMap = new HashMap<>();

    private BigInteger createSharedKey(final BigInteger otherPublicKey, final BigInteger p) {
        return otherPublicKey.modPow(myPrivateKey, p);
    }

    private BigInteger createPublicKey(final BigInteger g, final BigInteger p) {
        return g.modPow(myPrivateKey, p);
    }

    protected Packet interceptKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey,
                                          String source, String destination) {

        final var dest = registry.get(destination);

        //part of this challenge is to toy with G
        final BigInteger destG = gCallback == null ? g : gCallback.apply(p);

        //man in the middle time
        // send my own parameters to the destination,
        // and use the public key that I get back to create a shared key with that party
        final var publicKeyForD = createPublicKey(destG, p);
        final KeyExchange kxForD = new KeyExchange(destG, p, publicKeyForD);
        final Packet forDest = new Packet(source, destination, kxForD);
        final var responsePacket = dest.receivePacket(forDest);
        final var responsePayload = responsePacket.getPayload();

        final KeyExchange kxFromD = validateAndReturnPayloadByType(responsePayload, KeyExchange.class);

        final var sharedKeyWithD = createSharedKey(kxFromD.getPublicKey(), p);
        log.info("\nThe public key sent to d was {}\nthe shared key was {}\n(P - G) = {}\nG was {}",
                publicKeyForD, sharedKeyWithD, p.subtract(destG), destG);
        sharedKeyMap.put(dest.getName(), sharedKeyWithD);

        //now for the source
        // they gave me their public key, so I can just derive a shared key with them
        final BigInteger sourceSharedKey = createSharedKey(sourcePublicKey, p);
        sharedKeyMap.put(source, sourceSharedKey);

        //return a public key to the source
        final KeyExchange kxForSource = new KeyExchange(g, p, createPublicKey(g, p));
        return new Packet(responsePacket.getSource(), responsePacket.getDestination(), kxForSource);
    }

    protected Packet interceptMessage(Packet packet) {
        final String source = packet.getSource();
        final String destination = packet.getDestination();
        final byte[] message = (byte[]) packet.getPayload();

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

        //build a packet for the destination
        final Packet destPacket = new Packet(source, destination, reEncrypted);

        //send to destination and get response
        final var d = registry.get(destination);
        final var response = d.receivePacket(destPacket);
        byte[] rMsg = validateAndReturnPayloadByType(response.getPayload(), byte[].class);

        //do the same in reverse
        final var dMsgIv = splitIntoMsgAndIv(rMsg);
        final byte[] dDecrypted = decrypt(dSharedKey, dMsgIv.getLeft(), dMsgIv.getRight());
        validateExpectedMessage(new String(dDecrypted));

        return new Packet(response.getSource(), response.getDestination(),
                encrypt(sSharedKey, dDecrypted, dMsgIv.getRight()));
    }
}
