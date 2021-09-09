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

/**
 * an abstract man in the middle class providing common functions
 * a man in the middle is a weird mix between a network router and a diffie hellman party
 * a lot of this same logic can be found in a diffie hellman party
 */
@Slf4j
@Setter
public abstract class AbstractManInTheMiddle extends NetworkRouter {
    private final SHA1Digest sha1 = new SHA1Digest();
    private String expectedMessage;

    protected abstract Packet interceptKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey,
                                                   String source, String destination);

    protected abstract Packet interceptMessage(Packet packet);

    @Override
    public Packet route(Packet packet) {
        validatePartyRegistry(packet.getDestination());
        validatePartyRegistry(packet.getSource());

        Packet response = null;
        if (packet.getPayload() instanceof KeyExchange) {
            final KeyExchange kx = (KeyExchange) packet.getPayload();
            response = interceptKeyExchange(kx.getG(), kx.getP(), kx.getPublicKey(),
                    packet.getSource(), packet.getDestination());
        } else if (packet.getPayload() instanceof byte[]) {
            response = interceptMessage(packet);
        }

        if (response == null) {
            return registry.get(packet.getSource()).receivePacket(packet);
        } else {
            return response;
        }
    }


    /**
     * given a shared key, a message and an iv, decrypt
     *
     * @param sharedKey the shared key
     * @param message the message
     * @param iv the init vector
     * @return the decrypted message
     */
    protected byte[] decrypt(final BigInteger sharedKey, final byte[] message, final byte[] iv) {
        final byte[] keyHash = getKeyHashFromKey(sharedKey);
        final CBC cbc = new CBC(ByteArrayUtil.sliceByteArray(keyHash, 0, 16));
        return cbc.decryptAsByteArray(message, iv);
    }

    /**
     * given a key, a message, and an iv, encrypt
     * @param sharedKey the shared key
     * @param plaintext the plaintext message
     * @param iv the init vector
     * @return a concatenation of the encrypted message and the iv
     */
    protected byte[] encrypt(final BigInteger sharedKey, final byte[] plaintext, final byte[] iv) {
        final byte[] encSharedKeyHash = getKeyHashFromKey(sharedKey);
        final var cbc = new CBC(ByteArrayUtil.sliceByteArray(encSharedKeyHash, 0 , 16));
        final byte[] e = cbc.encryptToByteArray(plaintext, iv);
        return ByteArrayUtil.concatenate(e, iv);
    }

    /**
     * throw an exception if the message is not equal to the expected message property
     * @param actualMessage the actual message
     */
    protected void validateExpectedMessage(final String actualMessage) {
        log.info("man in the middle slice! {}", actualMessage);
        if (!StringUtils.equals(expectedMessage, this.expectedMessage)) {
            throw new CryptopalsException(String.format("Expected message '%s' did not match actual message '%s'",
                    this.expectedMessage, actualMessage));
        }
    }

    /**
     * do the grunt work of taking a big integer shared key and turning it into a
     * slice of a sha1 hash to be used for an encryption key
     * @param key the biginteger key
     * @return the key hash byte array
     */
    private byte[] getKeyHashFromKey(final BigInteger key) {
        final var keyArray = key.toByteArray();
        final byte[] keyHash = new byte[sha1.getDigestSize()];
        sha1.update(keyArray, 0, keyArray.length);
        sha1.doFinal(keyHash, 0);
        return ByteArrayUtil.sliceByteArray(keyHash, 0, 16);
    }


    /**
     * assuming the iv is the last 16 bytes of the supplied message,
     * split the message and iv apart and return it as a pair of byte arrays
     * @param message concatenated message
     * @return pair of byte arrays
     */
    protected Pair<byte[], byte[]> splitIntoMsgAndIv(byte[] message) {
        final int cutPoint = message.length - 16;
        final byte[] iv = ByteArrayUtil.sliceByteArray(message, cutPoint, 16);
        final byte[] actualMsg = ByteArrayUtil.sliceByteArray(message, 0, cutPoint);
        return Pair.of(actualMsg, iv);
    }

    /**
     * checks to see if the payload is assignable as the submitted class
     * if it is, it casts it and returns it as the stated class
     *
     * @param payload the payload
     * @param type the class
     * @param <T> generic type param
     * @return payload casted as T
     */
    protected <T> T validateAndReturnPayloadByType(final Object payload, final Class<T> type) {
        if(!(type.isAssignableFrom(payload.getClass()))) {
            throw new CryptopalsException(String.format("Expected a %s but instead got a %s",
                    type.getSimpleName(), payload.getClass().getSimpleName()
            ));
        }
        @SuppressWarnings("unchecked") T response =  (T) payload;
        return response;
    }
}
