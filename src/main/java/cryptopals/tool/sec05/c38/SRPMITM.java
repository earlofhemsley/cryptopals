package cryptopals.tool.sec05.c38;

import static cryptopals.CommonConstants.G;
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
            returnPayload = authenticate(a, packet.getDestination());
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
        crk.b = new BigInteger(1, ByteArrayUtil.randomBytes(4, "seed"));
        crk.salt = Hex.toHexString(ByteArrayUtil.randomBytes(6, "yay"));
        crk.u = new BigInteger(1, ByteArrayUtil.randomBytes(16, "my girl"));

        //build B
        final BigInteger B = g.modPow(crk.b, n);

        //persist to local cache
        localCache.put(username, crk);

        //return salt, B, u
        return new SimplifiedSRPKeyEx(crk.getSalt(), B, crk.u);
    }

    private boolean authenticate(Auth auth, String destination) {
        final Crackable crk = localCache.getOrDefault(auth.getUsername(), new Crackable());
        crk.kSalt = auth.getKSalt();
        return StringUtils.equals(destination, crk.serverName);
    }

    @SneakyThrows
    public Pair<String, String> crackAPass(final String clientUsername) {
        final Crackable crk = Optional.ofNullable(localCache.get(clientUsername))
                .orElseThrow(() -> new CryptopalsException("could not find user in local cache: " + clientUsername));
        noNullCrackableFields(crk);

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

        return Pair.of(cracked, crk.serverName);
    }

    private static void noNullCrackableFields(Crackable subject) {
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
        if (!nullFields.isEmpty()) {
            throw new CryptopalsException(String.format("%s is/are null fields in this crackable: %s",
                    String.join(", ", nullFields), subject));
        }
    }

    @Data
    private static class Crackable {
        private String serverName;
        private BigInteger A;
        private BigInteger u;
        private BigInteger b;
        private String salt;
        private byte[] kSalt;
    }
}
