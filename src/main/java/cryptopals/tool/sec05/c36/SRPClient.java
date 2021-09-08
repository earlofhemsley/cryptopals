package cryptopals.tool.sec05.c36;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.MT19937_32;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.utils.ByteArrayUtil;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;

public class SRPClient implements NetworkNode {
    private final String name;
    private final NetworkRouter network;
    private final BigInteger g;
    private final BigInteger k;
    private final BigInteger N;

    public SRPClient(String name, NetworkRouter network, BigInteger g, BigInteger k, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.k = k;
        this.N = n;

        network.register(this);
    }

    private final SHA256Digest sha256Digest = new SHA256Digest();

    //privateKey
    private final BigInteger a = BigInteger.valueOf(Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt()));

    @Override
    public String getName() {
        return name;
    }

    // must override, even tho probably won't use
    @Override
    public NetworkRouter.Packet receivePacket(NetworkRouter.Packet packet) {
        return null;
    }

    /**
     * register v, s, and I with the server
     * @param username the username
     * @param password the password
     * @param serverName the intended server
     */
    public void register(final String username, final String password, final String serverName) {
        final int salt = Math.abs(new MT19937_32(System.currentTimeMillis()).nextInt());
        final byte[] xH = new byte[sha256Digest.getDigestSize()];
        final byte[] input = ByteArrayUtil.concatenate(ByteArrayUtil.intToByteArray(salt), password.getBytes());
        sha256Digest.update(input, 0, input.length);
        sha256Digest.doFinal(xH,0);
        final BigInteger x = new BigInteger(1, xH);
        final BigInteger v = g.modPow(x, N);

        //package it all up
        final NetworkRouter.SRPReg reg = new NetworkRouter.SRPReg(username, salt, v);

        //networking
        final NetworkRouter.Packet response = network.route(new NetworkRouter.Packet(this.name, serverName, reg));
        final Boolean accepted = validateAndReturnPayloadByType(response.getPayload(), Boolean.class);
        if (accepted == null || !accepted) {
            throw new CryptopalsException("registration failed");
        }
    }

    public void createSharedKey() {}



}
