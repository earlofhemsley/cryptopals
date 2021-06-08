package cryptopals.tool.sec04;

import cryptopals.tool.AbstractAdminRightsOracle;
import cryptopals.tool.CBC;

import java.nio.charset.StandardCharsets;

public class C27_SameKeyIVAdminRightsOracle extends AbstractAdminRightsOracle {

    private final CBC cbc;
    private final byte[] iv;

    public C27_SameKeyIVAdminRightsOracle(final byte[] key) {
        this.cbc = new CBC(key);
        this.iv = key;
    }

    @Override
    protected byte[] encrypt(String input) {
        return cbc.encryptToByteArray(input.getBytes(StandardCharsets.UTF_8), iv);
    }

    @Override
    protected String decrypt(byte[] input) {
        return cbc.decryptAsString(input, iv);
    }
}
