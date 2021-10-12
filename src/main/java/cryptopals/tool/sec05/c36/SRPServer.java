package cryptopals.tool.sec05.c36;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.MT19937_32;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.tool.sec05.NetworkRouter.Auth;
import cryptopals.tool.sec05.NetworkRouter.Packet;
import cryptopals.tool.sec05.NetworkRouter.SRPKeyEx;
import cryptopals.tool.sec05.NetworkRouter.SRPReg;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import lombok.Getter;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Getter
public class SRPServer implements NetworkNode {
    private final String name;
    private final NetworkRouter network;
    private final BigInteger g;
    private final BigInteger k;
    private final BigInteger n;

    private final Map<String, SRPReg> registry = new HashMap<>();
    private final Map<String, byte[]> sharedKeys = new HashMap<>();

    public SRPServer(String name, NetworkRouter network, BigInteger g, BigInteger k, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.k = k;
        this.n = n;

        network.register(this);
    }

    /**
     * routing method
     * @param packet incoming package
     * @return response packet
     */
    @Override
    public Packet receivePacket(Packet packet) {
        validatePacket(packet);

        final Object responsePayload;
        if (packet.getPayload() instanceof SRPReg) {
            responsePayload = receiveRegRequest((SRPReg) packet.getPayload());
        } else if (packet.getPayload() instanceof SRPKeyEx) {
            responsePayload = receiveExchangeRequest((SRPKeyEx) packet.getPayload());
        } else if (packet.getPayload() instanceof Auth) {
            responsePayload = receiveAuthRequest((Auth) packet.getPayload());
        } else {
            throw new CryptopalsException("Unable to handle incoming packet because it was of an " +
                    "unrecognized type: " + packet.getPayload().getClass().getSimpleName());
        }

        return new Packet(this.name, packet.getSource(), responsePayload);
    }

    /**
     * receive a registration request
     * @param incoming the incoming reg request
     * @return boolean indicating reg was successful
     */
    private boolean receiveRegRequest(final SRPReg incoming) {
        registry.put(incoming.getUsername(), incoming);
        return true;
    }

    /**
     * receive a key exchange request.
     * build the public key B
     * determine the strong shared key K
     * store K
     * @param keyEx the incoming key exchange payload
     * @return an outgoing key exchange payload
     */
    private SRPKeyEx receiveExchangeRequest(final SRPKeyEx keyEx) {
        //verify we know who the source is
        final String username = keyEx.getText();
        validateRegistry(registry, username);

        //make one-time private key
        final BigInteger b = BigInteger.valueOf(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));

        //get the srp reg
        final var regInfo = registry.get(username);
        final BigInteger v = regInfo.getV();
        final byte[] salt;
        try {
            salt = Hex.decodeHex(regInfo.getSalt());
        } catch (DecoderException e) {
            throw new CryptopalsException("Could not decode salt", e);
        }

        //build B
        final BigInteger B = (k.multiply(v)).add(g.modPow(b, n));

        //build the shared key and save it
        final BigInteger A = keyEx.getPublicKey();
        final BigInteger u = new BigInteger(1,
                HashUtil.getSha256Hash(ByteArrayUtil.concatenate(A.toByteArray(), B.toByteArray())));
        final BigInteger S = (A.multiply(v.modPow(u, n))).modPow(b, n);
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        final byte[] hmacKSalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt));
        sharedKeys.put(username, hmacKSalt);

        //return the public key and salt
        return new SRPKeyEx(regInfo.getSalt(), B);
    }

    /**
     * validates a strong session key Kc against the locally stored session key Ks
     *
     * @param auth the auth payload from the client
     * @return boolean indicating successful authentication
     */
    private boolean receiveAuthRequest(final Auth auth) {
        validateRegistry(sharedKeys, auth.getUsername());
        final byte[] Ks = sharedKeys.get(auth.getUsername());
        return Arrays.equals(Ks, auth.getKSalt());
    }

    private static void validateRegistry(Map<String, ?> map, final String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException(String.format("%s is not a known user. register first",
                    key));
        }
    }
}
