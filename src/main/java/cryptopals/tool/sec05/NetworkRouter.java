package cryptopals.tool.sec05;

import lombok.Data;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public abstract class NetworkRouter {
    protected final Map<String, DiffieHellmanParty> registry = new HashMap<>();

    public void register(DiffieHellmanParty party) {
        registry.put(party.getName(), party);
    }

    public abstract Packet route(Packet packet);

    protected void validatePartyRegistry(final String partyName) {
        if (!registry.containsKey(partyName)) {
            throw new IllegalArgumentException(partyName + " is not a known party");
        }
    }

    @Data
    public static final class Packet {
        private final String source;
        private final String destination;
        private final Object payload;
    }

    @Data
    public static final class KeyExchange {
        private final BigInteger g;
        private final BigInteger p;
        private final BigInteger publicKey;
    }

    @Data
    public static final class EncryptedMessage {
        private final byte[] message;
    }
}
