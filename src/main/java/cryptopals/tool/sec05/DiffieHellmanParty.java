package cryptopals.tool.sec05;

import lombok.RequiredArgsConstructor;

import java.math.BigInteger;

/**
 * a party for use in diffie hellman key exchanges
 * ... generally, the secret key would be internally created
 * we allow it to be set for use in parameterized tests across a wide set of secret keys
 * however, there is no getter on that secret key, so it is not publicly available
 */
@RequiredArgsConstructor
public class DiffieHellmanParty {

    private final BigInteger g;
    private final BigInteger p;
    private final BigInteger secretKey;

    /**
     * build a public key using modpow for other parties to use
     * @return the public key
     */
    public BigInteger getPublicKey() {
        return g.modPow(secretKey, p);
    }

    /**
     * given a provided public key from another party, build a shared key
     * @param otherPartyPublic the other party's public key
     * @return the shared key
     */
    public BigInteger getSharedKey(final BigInteger otherPartyPublic) {
        return otherPartyPublic.modPow(secretKey, p);
    }
}
