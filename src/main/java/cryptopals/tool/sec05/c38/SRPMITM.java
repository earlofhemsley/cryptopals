package cryptopals.tool.sec05.c38;

import static com.google.common.base.Preconditions.checkArgument;
import static org.bouncycastle.util.encoders.Hex.decode;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.sec05.NetworkRouter;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class SRPMITM extends NetworkRouter {
    private final Map<String, Crackable> localCache = new HashMap<>();

    private final String dictFilePath;
    private final BigInteger g;
    private final BigInteger n;

    @Override
    public Packet route(Packet packet) {
        Object returnPayload = null;
        if (packet.getPayload() instanceof SimplifiedSRPKeyEx) {
            SimplifiedSRPKeyEx x = (SimplifiedSRPKeyEx) packet.getPayload();
            returnPayload = keyExchange(x, packet.getDestination());
        } else if (packet.getPayload() instanceof Auth) {
            Auth a = (Auth) packet.getPayload();
            returnPayload = serverAuthenticate(a, packet.getDestination());
        }
        if (returnPayload == null) {
            return registry.get(packet.getDestination()).receivePacket(packet);
        } else {
            return new Packet(packet.getDestination(), packet.getSource(), returnPayload);
        }
    }

    private SimplifiedSRPKeyEx keyExchange(SimplifiedSRPKeyEx cx, String serverName) {
        //validate registry
        final String username = cx.getText();

        //base var setup
        final Crackable crk = localCache.getOrDefault(username, new Crackable());
        crk.serverName = serverName;
        crk.A = cx.getPublicKey();
        crk.b = new BigInteger(1, ByteArrayUtil.randomBytes(4));
        crk.salt = Hex.toHexString(ByteArrayUtil.randomBytes(6));
        crk.u = new BigInteger(1, ByteArrayUtil.randomBytes(16));

        //build B
        final BigInteger B = g.modPow(crk.b, n);

        //persist to local cache
        localCache.put(username, crk);

        //return salt, B, u
        return new SimplifiedSRPKeyEx(crk.getSalt(), B, crk.u);
    }

    private boolean serverAuthenticate(Auth auth, String destination) {
        final Crackable crk = localCache.getOrDefault(auth.getUsername(), new Crackable());
        crk.kSalt = auth.getKSalt();
        return StringUtils.equals(destination, crk.serverName);
    }

    @SneakyThrows
    public Pair<String, String> crackAPass(final String clientUsername) {
        final Crackable crk = Optional.ofNullable(localCache.get(clientUsername))
                .orElseThrow(() -> new CryptopalsException("could not find user in local cache: " + clientUsername));
        noNullCrackableFields(crk, false);

        File f = new File(dictFilePath);

        String cracked = null;
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String candidatePass;
            byte[] ssalt = decode(crk.salt);
            while(cracked == null && (candidatePass = r.readLine()) != null) {
                //do the cracking
                final BigInteger x = new BigInteger(1,
                        HashUtil.getSha256Hash(ByteArrayUtil.concatenate(ssalt, candidatePass.getBytes()))
                );
                final BigInteger v = g.modPow(x, n);
                final BigInteger S = (crk.A.multiply(v.modPow(crk.u, n))).modPow(crk.b, n);
                final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
                final byte[] kSalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, ssalt));
                if (Arrays.equals(crk.kSalt, kSalt)) {
                    cracked = candidatePass;
                }
            }
        }

        crk.password = cracked;
        return Pair.of(cracked, crk.serverName);
    }

    private static void noNullCrackableFields(Crackable subject, boolean requirePassword) {
        final List<String> nullFields =
                Arrays.stream(Crackable.class.getDeclaredFields())
                        .filter(field -> {
                            try {
                                return Objects.isNull(field.get(subject));
                            } catch (IllegalAccessException e) {
                                throw new CryptopalsException("could get field " + field.getName(), e);
                            }
                        })
                        .map(Field::getName)
                        .collect(Collectors.toList());

        if (!requirePassword) {
            nullFields.removeIf(field -> StringUtils.equals(field, "password"));
        }

        if (!nullFields.isEmpty()) {
            throw new CryptopalsException(String.format("%s is/are null fields in this crackable: %s",
                    String.join(", ", nullFields), subject));
        }
    }

    public boolean authenticateAsClient(final String username) {
        final String fakeClientName = "client1351";
        checkArgument(StringUtils.isNotBlank(username), "username is required");
        final Crackable crk = Optional.ofNullable(localCache.get(username))
                .orElseThrow(() -> new IllegalArgumentException(String.format("username %s is not known", username)));
        noNullCrackableFields(crk, true);

        final BigInteger a = new BigInteger(1, ByteArrayUtil.randomBytes(4));
        final BigInteger A = g.modPow(a, n);
        final var server = registry.get(crk.serverName);
        final SimplifiedSRPKeyEx ikx = new SimplifiedSRPKeyEx (username, A, null);
        Packet p = server.receivePacket(new Packet(fakeClientName, crk.serverName, ikx));
        if (!(p.getPayload() instanceof SimplifiedSRPKeyEx)) {
            throw new CryptopalsException("Could not complete exchange");
        }
        final SimplifiedSRPKeyEx skx = (SimplifiedSRPKeyEx) p.getPayload();

        final byte[] salt = Hex.decode(skx.getText());
        final BigInteger x = new BigInteger(1,
                HashUtil.getSha256Hash(ByteArrayUtil.concatenate(salt, crk.password.getBytes())));
        final BigInteger S = skx.getPublicKey().modPow(a.add(skx.getU().multiply(x)), n);
        final byte[] K = HashUtil.getSha256Hash(S.toByteArray());
        final byte[] Ksalt = HashUtil.getSha256Hmac(ByteArrayUtil.concatenate(K, salt));

        final Auth auth = new Auth(username, Ksalt);
        p = server.receivePacket(new Packet(fakeClientName, crk.serverName, auth));
        if (!(p.getPayload() instanceof Boolean)) {
            throw new CryptopalsException("could not auth");
        }
        return (Boolean) p.getPayload();
    }


    @Data
    private static class Crackable {
        private String serverName;
        private BigInteger A;
        private BigInteger u;
        private BigInteger b;
        private String salt;
        private byte[] kSalt;

        private String password;
    }
}
