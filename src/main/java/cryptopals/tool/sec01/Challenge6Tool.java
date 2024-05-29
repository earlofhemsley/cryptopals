package cryptopals.tool.sec01;

import cryptopals.tool.Chi;
import cryptopals.tool.XOR;
import cryptopals.utils.ByteArrayUtil;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * a tool dedicated to resolving challenge 6
 */
public class Challenge6Tool {

    /**
     * given a message and no key, figure out what the key is, and decrypt the message
     *
     * this is the solution to challenge six
     */
    public static String breakTheCipher(String input) {
        byte[] contentBytes = Base64.getDecoder().decode(input);

        HashMap<Integer, Double> hammingPairs = new HashMap<>();

        //find the hamming distance between blocks of the input
        for (int candidateKeySize = 2; candidateKeySize <= 40; candidateKeySize++) {
            byte[] firstNBytes = ByteArrayUtil.sliceByteArray(contentBytes, 0, candidateKeySize);
            byte[] secondNBytes = ByteArrayUtil.sliceByteArray(contentBytes, candidateKeySize, candidateKeySize);
            byte[] thirdNBytes = ByteArrayUtil.sliceByteArray(contentBytes, candidateKeySize * 2, candidateKeySize);
            byte[] fourthNBytes = ByteArrayUtil.sliceByteArray(contentBytes, candidateKeySize * 3, candidateKeySize);
            double hammingDist1 = (double) calculateHammingDistance(firstNBytes, secondNBytes) / candidateKeySize;
            double hammingDist2 = (double) calculateHammingDistance(secondNBytes, thirdNBytes) / candidateKeySize;
            double hammingDist3 = (double) calculateHammingDistance(thirdNBytes, fourthNBytes) / candidateKeySize;
            double averageHammingDistance = (hammingDist1 + hammingDist2 + hammingDist3) / 3;
            hammingPairs.put(candidateKeySize, averageHammingDistance);
        }

        //get the best three hamming distances
        Integer[] bestSizes = hammingPairs.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue())
                .limit(3)
                .map(Map.Entry::getKey)
                .toArray(Integer[]::new);

        String best = null;
        double lowFullScore = Double.MAX_VALUE;
        for (int keySize : bestSizes) {
            //break the cipher text into blocks of length k
            //matrix
            int matrixHeight = (contentBytes.length % keySize == 0) ? contentBytes.length/keySize : contentBytes.length/keySize + 1;
            byte[][] matrix = new byte[matrixHeight][keySize];
            for (int i = 0; i<matrixHeight; i++){
                matrix[i] = ByteArrayUtil.sliceByteArray(contentBytes,i*keySize, keySize);
            }

            //transpose the blocks. group 1 is the first byte of each block, group 2 is the second, etc
            final byte[][] transposed = ByteArrayUtil.transposeByteMatrix(matrix);

            //decrypt each block as if it was single char xor
            byte[] keyBytes = new byte[keySize];
            for (int block = 0; block < keySize; block++) {
                int bestKeyInt = -1;
                double lowSingleScore = Double.MAX_VALUE;
                for (int c = 0; c < 256; c++) {
                    char[] decrypted = XOR.singleKeyXORAsCharArray(transposed[block], c);
                    double chiScore = Chi.score(decrypted);
                    if (chiScore < lowSingleScore) {
                        lowSingleScore = chiScore;
                        bestKeyInt = c;
                    }
                }
                assert bestKeyInt != -1;
                keyBytes[block] = (byte) bestKeyInt;
            }

            //decrypt the body
            String decryptedBody = new String(XOR.multiByteXOR(contentBytes, keyBytes));

            //chi square score the body
            double fullChi = Chi.score(decryptedBody.toCharArray());

            //check if better
            if(fullChi < lowFullScore) {
                best = decryptedBody;
            }
        }

        assert best != null;

        //return it
        return best;
    }

    public static int calculateHammingDistance(byte[] bytes1, byte[] bytes2) {
        if (bytes1.length != bytes2.length) {
            throw new IllegalArgumentException("arguments must be same length");
        }

        int count = 0;
        for (int i = 0; i < bytes1.length; i++) {
            byte one = bytes1[i];
            byte two = bytes2[i];
            byte xor = (byte) (one ^ two);
            for (int j = 0; j < 8; j++) {
                if( ((xor >> j) & 1) == 1 ) {
                    count++;
                }
            }
        }
        return count;
    }
}
