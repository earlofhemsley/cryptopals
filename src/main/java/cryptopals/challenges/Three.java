package cryptopals.challenges;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.HashMap;
import java.util.Map;

public class Three {

    private static final Map<Character, Double> ENGLISH_HISTOGRAM = new HashMap<>();
    static {
        ENGLISH_HISTOGRAM.put('E',12.02D);
        ENGLISH_HISTOGRAM.put('T',9.10D);
        ENGLISH_HISTOGRAM.put('A',8.12D);
        ENGLISH_HISTOGRAM.put('O',7.68D);
        ENGLISH_HISTOGRAM.put('I',7.31D);
        ENGLISH_HISTOGRAM.put('N',6.95D);
        ENGLISH_HISTOGRAM.put('S',6.28D);
        ENGLISH_HISTOGRAM.put('R',6.02D);
        ENGLISH_HISTOGRAM.put('H',5.92D);
        ENGLISH_HISTOGRAM.put('D',4.32D);
        ENGLISH_HISTOGRAM.put('L',3.98D);
        ENGLISH_HISTOGRAM.put('U',2.88D);
        ENGLISH_HISTOGRAM.put('C',2.71D);
        ENGLISH_HISTOGRAM.put('M',2.61D);
        ENGLISH_HISTOGRAM.put('F',2.30D);
        ENGLISH_HISTOGRAM.put('Y',2.11D);
        ENGLISH_HISTOGRAM.put('W',2.09D);
        ENGLISH_HISTOGRAM.put('G',2.03D);
        ENGLISH_HISTOGRAM.put('P',1.82D);
        ENGLISH_HISTOGRAM.put('B',1.49D);
        ENGLISH_HISTOGRAM.put('V',1.11D);
        ENGLISH_HISTOGRAM.put('K',0.69D);
        ENGLISH_HISTOGRAM.put('X',0.17D);
        ENGLISH_HISTOGRAM.put('Q',0.11D);
        ENGLISH_HISTOGRAM.put('J',0.10D);
        ENGLISH_HISTOGRAM.put('Z',0.07D);
    }


    public static String decrypt(String hexEncodedInput) throws DecoderException {
        byte[] decodedInput = Hex.decodeHex(hexEncodedInput);

        String reigningChampion = null;
        double lowScore = Double.MAX_VALUE;

        for(int key = 0; key < 300; key++ ) {
            char[] decrypted = new char[decodedInput.length];
            for(int i = 0; i < decrypted.length; i++) {
                decrypted[i] = (char) (Byte.toUnsignedInt(decodedInput[i]) ^ key);
            }
            double candidateScore = chiSquaredScore(decrypted);
            if (candidateScore < lowScore) {
                reigningChampion = String.valueOf(decrypted);
                lowScore = candidateScore;
            }
        }
        return reigningChampion;
    }

    private static double chiSquaredScore(char[] input) {
        Map<Character, Integer> countMap = new HashMap<>();
        for (int cha = 'A'; cha <= 'Z'; cha++) { countMap.put((char) cha, 0); }

        //group letters by bucket
        for (char c : input) {
            char cUp = Character.toUpperCase(c);
            if (cUp < 'A' || cUp > 'Z') {
                continue;
            }
            countMap.put(cUp, countMap.get(cUp) + 1);
        }

        //divide number per bucket by total number of chars in string to get a % like the histogram
        Map<Character, Double> percentageMap = new HashMap<>();
        for (Map.Entry<Character, Integer> entry : countMap.entrySet()) {
            percentageMap.put(entry.getKey(), (double) entry.getValue() / (double) input.length);
        }

        //(observed - histogram) ^2 / histogram for every letter
        double totalScore = 0D;
        for (Map.Entry<Character, Double> histoEntry : ENGLISH_HISTOGRAM.entrySet()) {
            double o = percentageMap.get(histoEntry.getKey());
            double e = histoEntry.getValue();
            double singleScore = Math.pow((o-e), 2) / e;
            totalScore = totalScore + singleScore;
        }
        return totalScore;
    }
}
