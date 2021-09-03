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

    protected Packet interceptKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey,
                                          String source, String destination) {
        final var dest = registry.get(destination);

        //man in the middle time
        // send the fake public key to the destination
        final KeyExchange fakeKeyExchange = new KeyExchange(g, p, p);
        final Packet responsePacket = dest.receivePacket(new Packet(source, destination, fakeKeyExchange));

        // send the fake public key to the source as well
        return new Packet(responsePacket.getSource(), responsePacket.getDestination(), fakeKeyExchange);
    }


    protected Packet interceptMessage(Packet packet) {
        validatePartyRegistry(packet.getDestination());
        final var dest = registry.get(packet.getDestination());

        final byte[] message = validateAndReturnPayloadByType(packet.getPayload(), byte[].class);

        //if we did it right, the shared key is going to be ZERO, so use that to decrypt
        final var msgAndIv = splitIntoMsgAndIv(message);
        final byte[] decrypted = decrypt(BigInteger.ZERO, msgAndIv.getLeft(), msgAndIv.getRight());

        validateExpectedMessage(new String(decrypted));

        return dest.receivePacket(packet);
    }

}
