package cryptopals.tool.sec03;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.PRNG_CTR;

import java.util.regex.Pattern;

/**
 * An anti-class for the PRNG_CTR
 */
public class C24_PrngCtrBreaker {

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

}
