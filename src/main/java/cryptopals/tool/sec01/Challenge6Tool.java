package cryptopals.tool.sec01;

import cryptopals.utils.Chi;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.XOR;

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
     * @param input
     * @return
     */
    public static String breakTheCipher(String input) {
        final XOR xor = new XOR();
        final Chi chi = new Chi();
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
        for (int keysize : bestSizes) {
            //break the cipher text into blocks of length k
            //matrix
            int matrixHeight = (contentBytes.length % keysize == 0) ? contentBytes.length/keysize : contentBytes.length/keysize + 1;
            byte[][] matrix = new byte[matrixHeight][keysize];
            for (int i = 0; i<matrixHeight; i++){
                matrix[i] = ByteArrayUtil.sliceByteArray(contentBytes,i*keysize, keysize);
            }

            //transpose the blocks. group 1 is the first byte of each block, group 2 is the second, etc
            byte[][] transposed = new byte[keysize][matrixHeight];
            for (int y = 0; y < matrixHeight; y++) {
                for (int x = 0; x < keysize; x++) {
                    transposed[x][y] = matrix[y][x];
                }
            }

            //decrypt each block as if it was single char xor
            byte[] keybytes = new byte[keysize];
            for (int block = 0; block < keysize; block++) {
                int bestKeyInt = -1;
                double lowSingleScore = Double.MAX_VALUE;
                for (int c = 0; c < 256; c++) {
                    char[] decrypted = xor.singleKeyXOR(transposed[block], c);
                    double chiScore = chi.score(decrypted);
                    if (chiScore < lowSingleScore) {
                        lowSingleScore = chiScore;
                        bestKeyInt = c;
                    }
                }
                assert bestKeyInt != -1;
                keybytes[block] = (byte) bestKeyInt;
            }

            //decrypt the body
            String decryptedBody = new String(xor.multiByteXOR(contentBytes, keybytes));

            //chi square score the body
            double fullChi = chi.score(decryptedBody.toCharArray());

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
