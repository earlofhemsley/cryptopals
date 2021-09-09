package cryptopals.tool.sec05.c36;

import static java.math.BigInteger.ZERO;

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
        //choose a one-time private key
        final BigInteger a = BigInteger.valueOf(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));

        //build public key
        final BigInteger A = g.modPow(a, n);

        //package it up
        final SRPKeyEx keyEx = new SRPKeyEx(username, A);

        //route it
        Packet p = new Packet(this.name, serverName, keyEx);
        Packet response = this.network.route(p);
        validatePacket(response);
        final SRPKeyEx keyExS = validateAndReturnPayloadByType(response.getPayload(), SRPKeyEx.class);
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
        p = new Packet(this.name, serverName, hmacKSalt);
        response = network.route(p);
        validatePacket(response);

        return validateAndReturnPayloadByType(response.getPayload(), Boolean.class);
    }

    private BigInteger getLittleX(final byte[] salt, final String password) {
        final byte[] input = ByteArrayUtil.concatenate(salt, password.getBytes());
        final byte[] xH = HashUtil.getSha256Hash(input);
        return new BigInteger(1, xH);
    }
}
