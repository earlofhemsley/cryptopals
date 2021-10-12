package cryptopals.tool.sec05.c38;

import com.google.common.base.Preconditions;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.tool.sec05.NetworkRouter.Auth;
import cryptopals.tool.sec05.NetworkRouter.Packet;
import cryptopals.tool.sec05.NetworkRouter.SRPReg;
import cryptopals.tool.sec05.NetworkRouter.SimplifiedSRPKeyEx;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class SimplifiedSRPClient implements NetworkNode {

    @Getter
    private final String name;
    private final BigInteger g;
    private final BigInteger n;

    @Setter
    private NetworkRouter network;

    public SimplifiedSRPClient(String name, NetworkRouter network, BigInteger g, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.n = n;

        network.register(this);
    }

    /**
     * no need to do anything with this for a client
     * @param packet incoming
     * @return null
     */
    @Override
    public Packet receivePacket(Packet packet) {
        return null;
    }

    public void register(final String username, final String password, final String serverName) {
        Preconditions.checkNotNull(username, "username required");
        Preconditions.checkNotNull(password, "password required");
        Preconditions.checkNotNull(serverName, "serverName required");

        final byte[] salt = ByteArrayUtil.randomBytes(6);
        final BigInteger x = getLittleX(salt, password);
        final BigInteger v = g.modPow(x, n);
        final SRPReg reg = new SRPReg(username, Hex.toHexString(salt), v);
        final Packet p = new Packet(this.name, serverName, reg);
        network.route(p);
    }

    @SneakyThrows
    public boolean authenticate(final String username, final String password, final String serverName) {
        Preconditions.checkNotNull(username, "username required");
        Preconditions.checkNotNull(password, "password required");
        Preconditions.checkNotNull(serverName, "serverName required");

        //get keys
        final BigInteger a = new BigInteger(1, ByteArrayUtil.randomBytes(4));
        final BigInteger A = g.modPow(a, n);

        //start exchange
        final SimplifiedSRPKeyEx ikx = new SimplifiedSRPKeyEx (username, A, null);
        Packet p = network.route(new Packet(this.name, serverName, ikx));
        final SimplifiedSRPKeyEx skx = validateAndReturnPayloadByType(p.getPayload(), SimplifiedSRPKeyEx.class);

        //unpack needed variables
        final byte[] salt = Hex.decode(skx.getText());
        final BigInteger x = getLittleX(salt, password);
        final BigInteger u = skx.getU();
        final BigInteger B = skx.getPublicKey();

        //build S
        final BigInteger aux = a.add(u.multiply(x));
        final BigInteger S = B.modPow(aux, n);

        //build K
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        final byte[] Ksalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt));

        p = network.route(new Packet(this.name, serverName, new Auth(username, Ksalt)));
        return validateAndReturnPayloadByType(p.getPayload(), Boolean.class);
    }

    private BigInteger getLittleX(final byte[] salt, final String password) {
        return new BigInteger(1, HashUtil.getSha256Hash(ByteArrayUtil.concatenate(salt, password.getBytes())));
    }
}
