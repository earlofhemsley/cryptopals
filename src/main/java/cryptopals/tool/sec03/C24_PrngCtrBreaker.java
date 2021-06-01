package cryptopals.tool.sec03;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.PRNG_CTR;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

/**
 * An anti-class for the PRNG_CTR
 */
public class C24_PrngCtrBreaker {

    /**
     * given a cipher text and a known plain text, extract the 16-bit key
     *
     * this only works when the key is a 16-bit key
     *
     * @param cipherText the cipher text
     * @param knownPlainText the known plain text
     * @return the key
     */
    public short bruteForcePRNGCTRKey(final byte[] cipherText, final String knownPlainText) {
        //there are fewer than 66k short values.
        // brute force, but double check with a pattern matcher ...
        // just in case by some freak accident the plain text shows up in the middle
        final var p = Pattern.compile("^\\w+" + knownPlainText + "$");
        for (short i = Short.MIN_VALUE; i < Short.MAX_VALUE; i++) {
            final PRNG_CTR prngCtr = new PRNG_CTR(i);
            final String candidate = prngCtr.decrypt(cipherText);
            if (p.matcher(candidate).find()) {
                return i;
            }
        }
        throw new CryptopalsException("Could not find a candidate key");
    }

    /**
     * given a token, determine if it was created using the current timestamp
     *
     * this uses brute force to check all timestamps over the last one minute
     *
     * @param token the token
     * @param requestBody a known plain text from which the token was derived
     * @return indicator of whether or not it was created with the current timestamp
     */
    public boolean keyIsCurrentTime(final String token, final String requestBody) {
        //brute force again ... assume it's within the last second
        final long ts = System.currentTimeMillis();
        for (long t = ts-1000L; t <= ts; t++) {
            final var prng = new PRNG_CTR((short) t);
            if(StringUtils.equals(token, prng.generatePasswordResetToken(requestBody))) {
                return true;
            }
        }
        return false;
    }
}
