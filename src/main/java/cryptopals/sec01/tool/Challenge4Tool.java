package cryptopals.sec01.tool;

import cryptopals.utils.Chi;
import cryptopals.utils.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.List;

/**
 * A tool for Section 1, Challenge 4.
 * Uses {@link XOR} and {@link Chi}
 */
public class Challenge4Tool {

    /**
     * consider a series of messages encrypted with single char encryption. find the message that actually decrypts
     *
     * this is the solution to challenge four
     * @param candidates
     * @return
     * @throws DecoderException
     */
    public String seekAndDestroy(List<String> candidates) throws DecoderException {
        final Chi chi = new Chi();
        final XOR xor = new XOR();

        String reigningChampion = null;
        double lowestScore = Double.MAX_VALUE;

        //find the best possible decryption
        for (String candidate : candidates) {
            byte[] decodedCandidate = Hex.decodeHex(candidate);
            for (int key = 0; key <= 256; key++) {
                char[] decrypted = xor.singleKeyXOR(decodedCandidate, key);
                double chiScore = chi.score(decrypted);
                if (chiScore < lowestScore) {
                    reigningChampion = String.valueOf(decrypted);
                    lowestScore = chiScore;
                }
            }
        }

        //return the string with the lowest score
        return reigningChampion == null ? null : reigningChampion.trim();
    }

}
