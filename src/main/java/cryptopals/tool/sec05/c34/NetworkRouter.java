package cryptopals.tool.sec05.c34;

import cryptopals.tool.sec05.DiffieHellmanParty;

import java.math.BigInteger;

public interface NetworkRouter {

    void register(DiffieHellmanParty party);

//    boolean isRegistered(String name);

    BigInteger initDHKeyExchange(DiffieHellmanParty source, String destination);

    byte[] routeMessage(byte[] message, String destination);
}
