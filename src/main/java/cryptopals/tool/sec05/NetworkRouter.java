package cryptopals.tool.sec05;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public abstract class NetworkRouter {
    protected final Map<String, DiffieHellmanParty> registry = new HashMap<>();

    public void register(DiffieHellmanParty party) {
        registry.put(party.getName(), party);
    }

    public abstract BigInteger initDHKeyExchange(BigInteger g, BigInteger p, BigInteger sourcePublicKey, String source, String destination);

    public abstract byte[] routeMessage(byte[] message, String source, String destination);

    protected void validatePartyRegistry(final String partyName) {
        if (!registry.containsKey(partyName)) {
            throw new IllegalArgumentException(partyName + " is not a known party");
        }
    }
}
