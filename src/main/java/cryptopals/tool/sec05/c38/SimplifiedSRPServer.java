package cryptopals.tool.sec05.c38;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.tool.sec05.NetworkRouter.Auth;
import cryptopals.tool.sec05.NetworkRouter.Packet;
import cryptopals.tool.sec05.NetworkRouter.SRPReg;
import cryptopals.tool.sec05.NetworkRouter.SimplifiedSRPKeyEx;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SimplifiedSRPServer implements NetworkNode {
    private final Map<String, SRPReg> srpRegMap = new HashMap<>();
    private final Map<String, byte[]> kMap = new HashMap<>();

    @Getter
    private final String name;
    private final NetworkRouter network;
    private final BigInteger g;
    private final BigInteger n;

    public SimplifiedSRPServer(String name, NetworkRouter network, BigInteger g, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.n = n;

        network.register(this);
    }

    @Override
    public Packet receivePacket(Packet packet) {
        validatePacket(packet);

        final Object responsePayload;
        if (packet.getPayload() instanceof SRPReg) {
            responsePayload = registration((SRPReg) packet.getPayload());
        } else if (packet.getPayload() instanceof SimplifiedSRPKeyEx) {
            responsePayload = keyExchange((SimplifiedSRPKeyEx) packet.getPayload());
        } else if (packet.getPayload() instanceof Auth) {
            responsePayload = authentication((Auth) packet.getPayload());
        } else {
            throw new CryptopalsException("Unable to handle incoming packet because it was of an " +
                    "unrecognized type: " + packet.getPayload().getClass().getSimpleName());
        }

        return new Packet(this.name, packet.getSource(), responsePayload);
    }

    private boolean registration(final SRPReg srpReg) {
        srpRegMap.put(srpReg.getUsername(), srpReg);
        return true;
    }

    @SneakyThrows
    private SimplifiedSRPKeyEx keyExchange(SimplifiedSRPKeyEx cx) {
        //validate registry
        final String username = cx.getText();
        validateRegistry(srpRegMap, username);

        //base var setup
        final SRPReg reg = srpRegMap.get(username);
        final BigInteger v = reg.getV();
        final byte[] salt = Hex.decodeHex(reg.getSalt());
        final BigInteger u = new BigInteger(1, ByteArrayUtil.randomBytes(16, "my girl"));

        //build B
        final BigInteger b = new BigInteger(1, ByteArrayUtil.randomBytes(4, "seed"));
        final BigInteger B = g.modPow(b, n);

        //find and store K
        final BigInteger A = cx.getPublicKey();
        final BigInteger S = (A.multiply(v.modPow(u, n))).modPow(b, n);
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        kMap.put(username, HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt)));

        //return salt, B, u
        return new SimplifiedSRPKeyEx(reg.getSalt(), B, u);
    }

    private boolean authentication(final Auth auth) {
        validateRegistry(kMap, auth.getUsername());
        final byte[] Ks = kMap.get(auth.getUsername());
        return Arrays.equals(Ks, auth.getKSalt());
    }


    private static void validateRegistry(Map<String, ?> map, final String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException(String.format("%s is not a known user. register first",
                    key));
        }
    }
}
