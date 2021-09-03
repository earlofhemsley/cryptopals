package cryptopals.tool.sec05;

import cryptopals.tool.CBC;
import cryptopals.tool.MT19937_32;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * a party for use in diffie hellman key exchanges
 * ... generally, the secret key would be internally created
 * we allow it to be set for use in parameterized tests across a wide set of secret keys
 * however, there is no getter on that secret key, so it is not publicly available
 */
@Slf4j
public class DiffieHellmanParty {
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final BigInteger P = new BigInteger(1, Hex.decode(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                    "fffffffffffff"
    ));

    private final SHA1Digest sha1 = new SHA1Digest();

    private final Map<String, BigInteger> knownSharedKeys = new HashMap<>();

    private final String name;
    private final BigInteger secretKey;
    private final NetworkRouter router;

    public DiffieHellmanParty(String name, NetworkRouter router) {
        this.name = name;
        secretKey = BigInteger.valueOf(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));
        this.router = router;
        router.register(this);
    }

    public DiffieHellmanParty(String name, BigInteger secretKey) {
        this.name = name;
        this.secretKey = secretKey;
        router = null;
    }

    public String getName() {
        return name;
    }

    /**
     * build a public key using modpow for other parties to use
     * @return the public key
     */
    public BigInteger getPublicKey(final BigInteger g, final BigInteger p) {
        return g.modPow(secretKey, p);
    }

    /**
     * given a provided public key from another party, build a shared key
     * @param otherPartyPublic the other party's public key
     * @return the shared key
     */
    public BigInteger getSharedKey(final BigInteger p,
                                   final BigInteger otherPartyPublic) {
        return otherPartyPublic.modPow(secretKey, p);
    }

    public NetworkRouter.Packet receivePacket(final NetworkRouter.Packet incoming) {
        if (!StringUtils.equals(incoming.getDestination(), this.getName())) {
            throw new IllegalStateException(String.format("Received a packet meant for %s, but I am %s",
                    incoming.getDestination(), this.getName()));
        }

        final Object responsePayload;
        if (incoming.getPayload() instanceof NetworkRouter.KeyExchange) {
            NetworkRouter.KeyExchange ipl = (NetworkRouter.KeyExchange) incoming.getPayload();
            final BigInteger myPublicKey = receiveKeyExchangeRequest(ipl.getG(), ipl.getP(), incoming.getSource(), ipl.getPublicKey());
            responsePayload = new NetworkRouter.KeyExchange(ipl.getG(), ipl.getP(), myPublicKey);
        } else if (incoming.getPayload() instanceof byte[]) {
            responsePayload = receiveEncryptedMessage(incoming.getSource(), (byte[]) incoming.getPayload());
        } else {
            throw new IllegalArgumentException("Unrecognized payload type: " + incoming.getPayload().getClass().getSimpleName());
        }
        return new NetworkRouter.Packet(this.getName(), incoming.getSource(), responsePayload);
    }

    /**
     * handle an incoming key exchange request from another party
     * @param g supplied g from source
     * @param p supplied p from source
     * @param name name of source
     * @param publicKey source's public key
     * @return this party's public key
     */
    private BigInteger receiveKeyExchangeRequest(BigInteger g, BigInteger p, String name, BigInteger publicKey) {
        knownSharedKeys.put(name, getSharedKey(p, publicKey));
        return getPublicKey(g, p);
    }

    /**
     * send a dh key exchange request to another party on the network
     * @param destination the desired destination party
     */
    public void sendKeyExchangeRequest(final String destination) {
        if (this.router == null) {
            throw new IllegalStateException("Unable to send. This has no network");
        }
        final NetworkRouter.KeyExchange payload = new NetworkRouter.KeyExchange(G, P, getPublicKey(G, P));
        final NetworkRouter.Packet response = router.route(new NetworkRouter.Packet(getName(), destination, payload));
        if (!(response.getPayload() instanceof NetworkRouter.KeyExchange)) {
            throw new IllegalArgumentException("did not receive a key exchange object in response: " + response.getPayload().toString());
        }
        knownSharedKeys.put(destination, getSharedKey(P, ((NetworkRouter.KeyExchange) response.getPayload()).getPublicKey()));
    }

    /**
     * encrypt and send a message to a desired destination, expecting the message to be echoed back unaltered
     * @param destination where the message is going to be sent
     * @param message the message to be sent
     * @return flag. true means the message that came back unaltered
     */
    public boolean sendEncryptedMessage(final String destination, final String message) {
        //derive the encryption key from the shared key hash for this destination
        final CBC cbc = retrieveCBCForNamedKey(destination);
        final byte[] iv = ByteArrayUtil.randomBytes(16);
        final byte[] encryptedMessage = cbc.encryptToByteArray(message.getBytes(), iv);

        final byte[] fullMessage = ByteArrayUtil.concatenate(encryptedMessage, iv);

        //send the message through the router and get a response
        final var response = router.route(new NetworkRouter.Packet(getName(), destination, fullMessage));
        if (!(response.getPayload() instanceof byte[])) {
            throw new IllegalStateException("response was not a byte array: " + response.getPayload().toString());
        }

        return Arrays.equals(fullMessage, (byte[]) response.getPayload());
    }

    /**
     * receive an encrypted message from a known source, decrypt it, log it, re-encrypt it, and return it.
     * if source not known, then an illegal argument * exception is thrown.
     * @param source known source of message
     * @param message the message
     * @return the re-encrypted message
     */
    private byte[] receiveEncryptedMessage(final String source, final byte[] message) {
        // decrypt the message
        final CBC cbc = retrieveCBCForNamedKey(source);

        //get the iv and the msg itself out of the parameter
        final int splitPoint = message.length - 16;
        final byte[] iv = ByteArrayUtil.sliceByteArray(message, splitPoint, 16);
        final byte[] toDecrypt = ByteArrayUtil.sliceByteArray(message, 0, message.length - 16);

        //decrypt
        final byte[] decrypted = cbc.decryptAsByteArray(toDecrypt, iv);
        log.info("message decrypted: {}", new String(decrypted));

        //re-encrypt and return the message
        final byte[] reEncrypted = cbc.encryptToByteArray(decrypted, iv);

        return ByteArrayUtil.concatenate(reEncrypted, iv);
    }

    /**
     * given a source name, build a CBC encryption object using the shared key
     * associated with that source
     * @param source the source
     * @return CBC encrypting object
     */
    private CBC retrieveCBCForNamedKey(final String source) {
        byte[] sharedKey = Optional.ofNullable(knownSharedKeys.get(source))
                .map(BigInteger::toByteArray)
                .orElseThrow(() -> new IllegalArgumentException(String.format("no shared key available for %s", source)));
        final byte[] encKeyHash = new byte[sha1.getDigestSize()];
        sha1.update(sharedKey, 0, sharedKey.length);
        sha1.doFinal(encKeyHash, 0);
        return new CBC(ByteArrayUtil.sliceByteArray(encKeyHash, 0, 16));
    }
}
