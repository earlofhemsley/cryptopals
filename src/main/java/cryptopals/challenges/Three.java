package cryptopals.challenges;

import cryptopals.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Three {

    public static String decrypt(byte[] decodedInput) throws DecoderException {

        String reigningChampion = null;
        double lowScore = Double.MAX_VALUE;

        for(int key = 0; key < 256; key++ ) {
            char[] decrypted = Utils.singleKeyXOR(decodedInput, key);
            double candidateScore = Utils.chiSquaredScore(decrypted);
            if (candidateScore < lowScore) {
                reigningChampion = String.valueOf(decrypted);
                lowScore = candidateScore;
            }
        }
        return reigningChampion;
    }

}
