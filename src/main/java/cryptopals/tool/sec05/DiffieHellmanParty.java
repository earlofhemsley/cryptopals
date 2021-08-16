package cryptopals.tool.sec05;

import cryptopals.tool.CBC;
import cryptopals.tool.MT19937_32;
import cryptopals.tool.sec05.c34.NetworkRouter;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;
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
    private BigInteger g = BigInteger.valueOf(2);
    private BigInteger p = new BigInteger(1, Hex.decode(
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

    public DiffieHellmanParty(BigInteger g, BigInteger p, String name, BigInteger secretKey) {
        this.g = g;
        this.p = p;
        this.name = name;
        this.secretKey = secretKey;
        router = null;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public String getName() {
        return name;
    }

    /**
     * build a public key using modpow for other parties to use
     * @return the public key
     */
    public BigInteger getPublicKey() {
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

    public BigInteger receiveKeyExchangeRequest(BigInteger g, BigInteger p, String name, BigInteger publicKey) {
        this.g = g;
        this.p = p;
        knownSharedKeys.put(name, getSharedKey(p, publicKey));
        return getPublicKey();
    }

    public void sendKeyExchangeRequest(final String destination) {
        if (this.router == null) {
            throw new IllegalStateException("Unable to send. This has no network");
        }
        final BigInteger destinationPublicKey = router.initDHKeyExchange(this, destination);
        knownSharedKeys.put(destination, getSharedKey(p, destinationPublicKey));
    }

    public boolean sendEncryptedMessage(final String destination, final String message) {
        //derive the encryption key from the shared key hash for this destination
        final CBC cbc = retrieveCBCForNamedKey(destination);
        final byte[] iv = ByteArrayUtil.randomBytes(16);
        final byte[] encryptedMessage = cbc.encryptToByteArray(message.getBytes(), iv);

        final byte[] fullMessage = ByteArrayUtil.concatenate(encryptedMessage, iv);

        //send the message through the router and get a response
        final byte[] response = router.routeMessage(fullMessage, this.name, destination);

        return Arrays.equals(fullMessage, response);
    }

    //echo bot
    public byte[] receiveEncryptedMessage(final String source, final byte[] message) {
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

    //derive the encryption key from the shared key hash for this destination
    private CBC retrieveCBCForNamedKey(final String keyName) {
        byte[] sharedKey = Optional.ofNullable(knownSharedKeys.get(keyName))
                .map(BigInteger::toByteArray)
                .orElseThrow(() -> new IllegalArgumentException(String.format("no shared key available for %s", keyName)));
        final byte[] encKeyHash = new byte[sha1.getDigestSize()];
        sha1.update(sharedKey, 0, sharedKey.length);
        sha1.doFinal(encKeyHash, 0);
        return new CBC(ByteArrayUtil.sliceByteArray(encKeyHash, 0, 16));
    }
}
