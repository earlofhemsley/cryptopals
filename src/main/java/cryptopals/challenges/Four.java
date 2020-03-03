package cryptopals.challenges;

import cryptopals.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.List;

public class Four {
    public static String seekAndDestroy(List<String> candidates) throws DecoderException {

        String reigningChampion = null;
        double lowestScore = Double.MAX_VALUE;

        //find the best possible decryption
        for (String candidate : candidates) {
            byte[] decodedCandidate = Hex.decodeHex(candidate);
            for (int key = 0; key <= 256; key++) {
                char[] decrypted = Utils.singleKeyXORDecrypt(decodedCandidate, key);
                double chiScore = Utils.chiSquaredScore(decrypted);
                if (chiScore < lowestScore) {
                    reigningChampion = String.valueOf(decrypted);
                    lowestScore = chiScore;
                }
            }
        }

        //return the string with the lowest score
        return reigningChampion.trim();
    }
}
