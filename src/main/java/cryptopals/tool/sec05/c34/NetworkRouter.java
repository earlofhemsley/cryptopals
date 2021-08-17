package cryptopals.tool.sec05.c34;

import cryptopals.tool.sec05.DiffieHellmanParty;

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
}
