package cryptopals.tool.sec04;

import cryptopals.tool.AbstractAdminRightsOracle;
import cryptopals.tool.CTR;
import cryptopals.utils.ByteArrayUtil;

/**
 * an implementing class of {@link cryptopals.tool.AbstractAdminRightsOracle} that uses CTR.
 * Designed specifically for Challenge 26
 */
public class C26_CTRAdminRightsOracle extends AbstractAdminRightsOracle {

    private static final byte[] KEY = ByteArrayUtil.randomBytes(16);
    private final CTR ctr = new CTR(KEY);

    @Override
    protected byte[] encrypt(String input) {
        return ctr.encrypt(input);
    }

    @Override
    protected String decrypt(byte[] input) {
        return ctr.decrypt(input);
    }
}
