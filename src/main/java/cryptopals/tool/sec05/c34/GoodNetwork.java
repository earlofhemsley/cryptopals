package cryptopals.tool.sec05.c34;

import cryptopals.tool.sec05.DiffieHellmanParty;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class GoodNetwork implements NetworkRouter {
    private final Map<String, DiffieHellmanParty> registry = new HashMap<>();

    @Override
    public void register(DiffieHellmanParty party) {
        registry.put(party.getName(), party);
    }

    @Override
    public BigInteger initDHKeyExchange(DiffieHellmanParty source, String destination) {
        if (!registry.containsKey(destination)) {
            throw new IllegalArgumentException(destination + " is not a known destination");
        }

        if(!registry.containsKey(source.getName())) {
            registry.put(source.getName(), source);
        }

        final var d = registry.get(destination);
        return d.receiveKeyExchangeRequest(source.getG(), source.getP(), source.getName(), source.getPublicKey());
    }

    @Override
    public byte[] routeMessage(byte[] message, String destination) {
        final var d = Optional.ofNullable(registry.get(destination))
                .orElseThrow(() -> new IllegalArgumentException(destination + " is not a known destination"));
        return d.receiveEncryptedMessage(message);
    }
}
