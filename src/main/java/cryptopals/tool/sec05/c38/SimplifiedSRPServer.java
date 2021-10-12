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
import lombok.Data;
import lombok.Getter;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SimplifiedSRPServer implements NetworkNode {
    private final Map<String, UserCache> localCache = new HashMap<>();

    @Getter
    private final String name;
    private final BigInteger g;
    private final BigInteger n;

    public SimplifiedSRPServer(String name, NetworkRouter network, BigInteger g, BigInteger n) {
        this.name = name;
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
        final UserCache c = localCache.getOrDefault(srpReg.getUsername(), new UserCache());
        c.setSalt(srpReg.getSalt());
        c.setV(srpReg.getV());
        localCache.put(srpReg.getUsername(), c);
        return true;
    }

    @SneakyThrows
    private SimplifiedSRPKeyEx keyExchange(SimplifiedSRPKeyEx cx) {
        //validate registry
        final String username = cx.getText();
        validateRegistry(localCache, username);

        //base var setup
        final UserCache user = localCache.get(username);
        final BigInteger v = user.v;
        final byte[] salt = Hex.decode(user.salt);
        final BigInteger u = new BigInteger(1, ByteArrayUtil.randomBytes(16));

        //build B
        final BigInteger b = new BigInteger(1, ByteArrayUtil.randomBytes(4));
        final BigInteger B = g.modPow(b, n);

        //find and store K
        final BigInteger A = cx.getPublicKey();
        final BigInteger S = (A.multiply(v.modPow(u, n))).modPow(b, n);
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        user.kSalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt));

        //persist to local cache
        localCache.put(username, user);

        //return salt, B, u
        return new SimplifiedSRPKeyEx(user.getSalt(), B, u);
    }

    private boolean authentication(final Auth auth) {
        validateRegistry(localCache, auth.getUsername());
        final UserCache crk = localCache.get(auth.getUsername());
        return Arrays.equals(crk.kSalt, auth.getKSalt());
    }


    private static void validateRegistry(Map<String, ?> map, final String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException(String.format("%s is not a known user. register first",
                    key));
        }
    }

    @Data
    private static class UserCache {
        private String salt;
        private BigInteger v;
        private byte[] kSalt;
    }
}
