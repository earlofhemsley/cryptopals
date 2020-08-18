package cryptopals.challenges;

import cryptopals.utils.Chi;
import cryptopals.utils.Utils;
import cryptopals.utils.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Section01 {
    /**
     * convert hex to base 64
     *
     * this is the solution for challenge 1
     * @param hexInput
     * @return
     * @throws DecoderException
     */
    static String convertHexToBase64(String hexInput) throws DecoderException {
        byte[] hextBytes = Hex.decodeHex(hexInput);
        return Base64.getEncoder().encodeToString(hextBytes);
    }

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

        for(int key = 0; key < 256; key++ ) {
            char[] decrypted = new XOR().singleKeyXOR(decodedInput, key);
            double candidateScore = new Chi().score(decrypted);
            if (candidateScore < lowScore) {
                reigningChampion = String.valueOf(decrypted);
                lowScore = candidateScore;
            }
        }
        return reigningChampion;
    }



    private static byte[] key = "ICE".getBytes();

    /**
     * encrypt a message with a repeating key. this is part of the solution to challenge five
     * @param toEncrypt
     * @return
     */
    public static String repeatingKeyEncrypt(String toEncrypt) {
        byte[] result = new XOR().multiByteXOR(toEncrypt.getBytes(), key);
        return String.valueOf(Hex.encodeHex(result));
    }

    /**
     * decrypt a message with a repeating key. this is part of the solution to challenge five
     * @param toDecrypt
     * @return
     * @throws DecoderException
     */
    public static String repeatingKeyDecrypt(String toDecrypt) throws DecoderException {
        byte[] hexDecoded = Hex.decodeHex(toDecrypt);
        byte[] decrypted = new XOR().multiByteXOR(hexDecoded, key);
        StringBuilder result = new StringBuilder();
        for (byte b : decrypted) {
            result.append((char)b);
        }
        return result.toString();
    }


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

        String debugString = Base64.getEncoder().encodeToString(contentBytes);
        assert debugString.equals(input);

        HashMap<Integer, Double> hammingPairs = new HashMap<>();

        //find the hamming distance between blocks of the input
        for (int candidateKeySize = 2; candidateKeySize <= 40; candidateKeySize++) {
            byte[] firstNBytes = Utils.sliceByteArray(contentBytes, 0, candidateKeySize);
            byte[] secondNBytes = Utils.sliceByteArray(contentBytes, candidateKeySize, candidateKeySize);
            byte[] thirdNBytes = Utils.sliceByteArray(contentBytes, candidateKeySize * 2, candidateKeySize);
            byte[] fourthNBytes = Utils.sliceByteArray(contentBytes, candidateKeySize * 3, candidateKeySize);
            double hammingDist1 = (double) Utils.calculateHammingDistance(firstNBytes, secondNBytes) / candidateKeySize;
            double hammingDist2 = (double) Utils.calculateHammingDistance(secondNBytes, thirdNBytes) / candidateKeySize;
            double hammingDist3 = (double) Utils.calculateHammingDistance(thirdNBytes, fourthNBytes) / candidateKeySize;
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
                matrix[i] = Utils.sliceByteArray(contentBytes,i*keysize, keysize);
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
                HashMap<Integer, Double> resultMap = new HashMap<>();
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

    /**
     * Decrypt a message in AES-ECB mode
     *
     * this is the solution to challenge 7
     * @param cipherTextBytes bytes of the cipher text string
     * @param cipherKeyBytes
     * @param cipherMode one of the public static ints attached to {@link Cipher}
     * @return a string of the decrypted bytes
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] AESInECBMode(byte[] cipherTextBytes, byte[] cipherKeyBytes, int cipherMode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");
        cipher.init(cipherMode, cipherKey);
        return cipher.doFinal(cipherTextBytes);
    }

    public static byte[] AESinECBModeWPadding(byte[] cipherTextBytes, byte[] cipherKeyBytes, int cipherMode) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //implement padding
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipherTextBytes = Section02.implementPKCS7Padding(cipherTextBytes, cipherKeyBytes.length);
        }

        var theFinal = Section01.AESInECBMode(cipherTextBytes, cipherKeyBytes, cipherMode);

        if (cipherMode == Cipher.DECRYPT_MODE) {
            theFinal = Section02.stripPCKS7Padding(theFinal);
        }

        return theFinal;
    }


    /**
     * given a series of messages, detect which of the messages was decrypted in ECB mode.
     *
     * this is the solution to challenge eight
     * @param cipherBytes
     * @return true if found, false otherwise
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws DecoderException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static boolean detectECBInCipherBytes(byte[] cipherBytes, byte[] cipherKeyBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");

        //decrypt
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        byte[] decryptedCipherBytes = cipher.doFinal(cipherBytes);

        if (cipherBytes.length % cipherKeyBytes.length != 0) {
            throw new IllegalBlockSizeException("message length must be a multiple of the cipher key length, which is " + cipherKeyBytes.length);
        }

        int loopIterations = decryptedCipherBytes.length/cipherKeyBytes.length;

        //break the decoded text into 16-byte blocks
        byte[][] decryptedBlocks = new byte[loopIterations][16];
        for (int i = 0; i < loopIterations; i++) {
            decryptedBlocks[i] = Arrays.copyOfRange(decryptedCipherBytes, i*16, (i*16)+16);
            //go back through what was already decrypted and check for equality
            for(int j = 0; j < i; j++) {
                if (Arrays.equals(decryptedBlocks[j], decryptedBlocks[i])) {
                    //if we found two bytes that decrypted out the same in this row,
                    // then this is a row that was encrypted with ECB
                    return true;
                }
            }
        }
        return false;
    }
}
