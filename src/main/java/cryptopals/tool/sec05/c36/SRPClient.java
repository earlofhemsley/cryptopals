package cryptopals.tool.sec05.c36;

import static java.math.BigInteger.ZERO;

import com.google.common.base.Preconditions;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.MT19937_32;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.tool.sec05.NetworkRouter.Packet;
import cryptopals.tool.sec05.NetworkRouter.SRPKeyEx;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;

public class SRPClient implements NetworkNode {

    private final String name;
    private final NetworkRouter network;
    private final BigInteger g;
    private final BigInteger k;
    private final BigInteger n;

    public SRPClient(String name, NetworkRouter network, BigInteger g, BigInteger k, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.k = k;
        this.n = n;

        network.register(this);
    }

    @Override
    public String getName() {
        return name;
    }

    // must override, even tho probably won't use
    @Override
    public Packet receivePacket(Packet packet) {
        return null;
    }

    /**
     * register v, s, and I with the server
     * @param username the username
     * @param password the password
     * @param serverName the intended server
     */
    public void register(final String username, final String password, final String serverName) {
        final byte[] salt = ByteArrayUtil.intToByteArray(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));
        final BigInteger x = getLittleX(salt, password);
        final BigInteger v = g.modPow(x, n);

        //package it all up
        final NetworkRouter.SRPReg reg = new NetworkRouter.SRPReg(username, Hex.encodeHexString(salt), v);

        //networking
        final Packet response = network.route(new Packet(this.name, serverName, reg));
        final Boolean accepted = validateAndReturnPayloadByType(response.getPayload(), Boolean.class);
        if (accepted == null || !accepted) {
            throw new CryptopalsException("registration failed");
        }
    }

    /**
     * given a previous registration, authenticate securely against the specified server
     * @param username username
     * @param password password
     * @param serverName desired server
     * @return boolean. indicates successful authentication
     * @throws DecoderException if a salt can't be decoded
     */
    public boolean authenticateSecurely(final String username, final String password, final String serverName)
            throws DecoderException {
        Preconditions.checkNotNull(username, "username required");
        Preconditions.checkNotNull(password, "password required");
        Preconditions.checkNotNull(serverName, "serverName required");

        //choose a one-time private key
        final BigInteger a = BigInteger.valueOf(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));

        //build public key
        final BigInteger A = g.modPow(a, n);

        //package it up
        final SRPKeyEx keyEx = new SRPKeyEx(username, A);

        //route it
        final SRPKeyEx keyExS = executeKeyExchange(keyEx, serverName);

        final BigInteger B = keyExS.getPublicKey();
        final byte[] salt = Hex.decodeHex(keyExS.getText());
        final BigInteger x = getLittleX(salt, password);

        //build shared key
        final byte[] uH = HashUtil.getSha256Hash(ByteArrayUtil.concatenate(A.toByteArray(), B.toByteArray()));
        final BigInteger u = new BigInteger(1, uH);
        final BigInteger aux = a.add(u.multiply(x));
        final BigInteger kgx = k.multiply(g.modPow(x, n));
        final BigInteger S = (B.subtract(kgx)).modPow(aux, n);
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        final byte[] hmacKSalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt));

        //build packet for authentication
        return executeAuthRequest(hmacKSalt, serverName);
    }

    /**
     * send a multiple of n as the private key. This will force the secret key to be 0, which makes the
     * shared key K constant, which makes it super easy to break SRP.
     * @param username the username
     * @param multiple the multiple of n
     * @param serverName the server being auth'd against
     * @return boolean indicating successful login
     * @throws DecoderException thrown when can't decode a salt
     */
    public boolean authenticateMaliciously(final String username, final BigInteger multiple, final String serverName)
            throws DecoderException {
        Preconditions.checkNotNull(username, "username required");
        Preconditions.checkNotNull(serverName, "serverName required");

        final SRPKeyEx keyEx = new SRPKeyEx(username, n.multiply(multiple));
        final SRPKeyEx keyExS = executeKeyExchange(keyEx, serverName);

        final byte[] K = HashUtil.getSha256Hash(ZERO.toByteArray());
        final byte[] hmacKSalt = HashUtil.getSha256Hmac(
                ByteArrayUtil.concatenate(K, Hex.decodeHex(keyExS.getText()))
        );

        //build packet for authentication
        return executeAuthRequest(hmacKSalt, serverName);
    }

    private SRPKeyEx executeKeyExchange(final SRPKeyEx keyEx, final String serverName) {
        Packet p = new Packet(this.name, serverName, keyEx);
        Packet response = this.network.route(p);
        validatePacket(response);
        return validateAndReturnPayloadByType(response.getPayload(), SRPKeyEx.class);
    }

    private boolean executeAuthRequest(final byte[] hmacKS, final String serverName) {
        final Packet p = new Packet(this.name, serverName, hmacKS);
        final Packet response = network.route(p);
        validatePacket(response);
        return validateAndReturnPayloadByType(response.getPayload(), Boolean.class);
    }

    private BigInteger getLittleX(final byte[] salt, final String password) {
        final byte[] input = ByteArrayUtil.concatenate(salt, password.getBytes());
        final byte[] xH = HashUtil.getSha256Hash(input);
        return new BigInteger(1, xH);
    }
}
