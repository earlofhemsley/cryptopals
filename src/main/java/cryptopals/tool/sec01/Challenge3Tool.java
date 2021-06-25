package cryptopals.tool.sec01;

import cryptopals.tool.Chi;
import cryptopals.tool.XOR;
import org.apache.commons.codec.DecoderException;

/**
 * A tool for challenge 3. Uses {@link Chi} and {@link XOR}
 */
public class Challenge3Tool {
    /**
     * Decrypt a message encrypted with single key encryption, scoring the message using X^2 goodness of fit test
     *
     * this is the solution to challenge 3
     * @param decodedInput
     * @return
     * @throws DecoderException
     */
    public static String decrypt(byte[] decodedInput) {

        String reigningChampion = null;
        double lowScore = Double.MAX_VALUE;

        for(int key = Byte.MIN_VALUE; key <= Byte.MAX_VALUE; key++ ) {
            char[] decrypted = new XOR().singleKeyXORToCharArray(decodedInput, key);
            double candidateScore = new Chi().score(decrypted);
            if (candidateScore < lowScore) {
                reigningChampion = String.valueOf(decrypted);
                lowScore = candidateScore;
            }
        }
        return reigningChampion;
    }

}
