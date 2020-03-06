package cryptopals.utils;

import java.util.HashMap;
import java.util.Map;

public class Utils {
    private Utils() {
        throw new AssertionError("Cannot instantiate");
    }

    private static final Map<Character, Double> ENGLISH_HISTOGRAM = new HashMap<>();
    static {
        ENGLISH_HISTOGRAM.put(' ',14.00D);
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

    public static char[] singleKeyXOR(byte[] input, int key) {
        char[] decrypted = new char[input.length];
        for(int i = 0; i < decrypted.length; i++) {
            decrypted[i] = (char) (Byte.toUnsignedInt(input[i]) ^ key);
        }
        return decrypted;
    }

    public static byte[] multiByteXOR(byte[] input, byte[] key) {
        byte[] xord = new byte[input.length];
        for(int i = 0; i < xord.length; i++) {
            xord[i] = (byte) (input[i] ^ key[i % key.length]);
        }
        return xord;
    }

    public static double chiSquaredScore(char[] input) {
        Map<Character, Integer> countMap = new HashMap<>();
        for (int cha = 'A'; cha <= 'Z'; cha++) { countMap.put((char) cha, 0); }
        countMap.put(' ', 0);

        //group letters by bucket
        for (char c : input) {
            char cUp = Character.toUpperCase(c);
            if (cUp != ' ' && (cUp < 'A' || cUp > 'Z')) {
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
