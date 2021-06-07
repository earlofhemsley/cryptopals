package cryptopals.tool.sec02;

import cryptopals.tool.AbstractAdminRightsOracle;
import cryptopals.tool.CBC;

import java.nio.charset.StandardCharsets;

/**
 * This tool aids in the accomplishment of challenge 16
 */
public class Challenge16Tool extends AbstractAdminRightsOracle {

    private final CBC cbc;
    private final byte[] iv;

    public Challenge16Tool(byte[] key, byte[] iv) {
        this.cbc = new CBC(key);
        this.iv = iv;
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
