package cryptopals.challenges;

import cryptopals.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Section02 {
    /**
     * given a message and a block size, implement pkcs7 padding on the message to make the message conform to the block size
     *
     * this is the solution to challenge nine
     *
     * @param messageBytes
     * @param blockSize
     * @return
     */
    public static byte[] implementPKCS7Padding(byte[] messageBytes, int blockSize) {
        if (blockSize >= 256 || blockSize <= 0) {
            throw new IllegalArgumentException("Block size can only be between 1 and 255, inclusive");
        }
        int numOfPaddingBytes = blockSize - messageBytes.length % blockSize;

        int newLength = (int) Math.ceil((double) messageBytes.length / blockSize) * blockSize;
        if (newLength == messageBytes.length) {
            newLength += blockSize;
        }

        byte[] paddedMessage = Arrays.copyOf(messageBytes, newLength);

        for (int i = messageBytes.length; i<messageBytes.length + numOfPaddingBytes; i++) {
            paddedMessage[i] = (byte) numOfPaddingBytes;
        }

        return paddedMessage;
    }

    public static byte[] AESinCBCMode(byte[] textBytes, final byte[] cipherKeyBytes, final byte[] iv, int cipherMode) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("cipherMode must be Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
        }

        //block size will be the size of the cipher key
        //make sure the iv and the cipherkey are the same size
        if (cipherKeyBytes.length != iv.length) {
            throw new IllegalArgumentException("cipher key and init vector must be the same length");
        }

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            //pad the message only if encrypting
            textBytes = Section02.implementPKCS7Padding(textBytes, cipherKeyBytes.length);
        } else if (textBytes.length % cipherKeyBytes.length != 0) {
            //make sure the message length is a multiple of the iv
            throw new IllegalArgumentException("When decrypting, the message's length must be a multiple of the key's length");
        }

        byte[] resultBytes = new byte[textBytes.length];
        byte[] previousBlock = iv;

        for (int n = 0; n < textBytes.length; n+=iv.length) {
            //get the nth block
            byte[] nthBlock = Utils.sliceByteArray(textBytes, n, iv.length);

            byte[] currentBlock;
            switch (cipherMode) {
                case Cipher.ENCRYPT_MODE:
                    byte[] xorNthBlock = Utils.multiByteXOR(nthBlock, previousBlock);
                    currentBlock = Section01.AESInECBMode(xorNthBlock, cipherKeyBytes, cipherMode);
                    previousBlock = currentBlock;
                    break;
                case Cipher.DECRYPT_MODE:
                    byte[] decNthBlock = Section01.AESInECBMode(nthBlock, cipherKeyBytes, cipherMode);
                    currentBlock = Utils.multiByteXOR(decNthBlock, previousBlock);
                    previousBlock = nthBlock;
                    break;
                default:
                    throw new IllegalArgumentException("illegal cipher mode");
            }

            for (int i = 0; i < iv.length; i++ ) {
                resultBytes[n+i] = currentBlock[i];
            }
        }

        //strip padding if decrypting
        if (cipherMode == Cipher.DECRYPT_MODE) {
            //get last byte
            int numToStrip = resultBytes[resultBytes.length - 1];
            int numToKeep = resultBytes.length - numToStrip;
            resultBytes = Utils.sliceByteArray(resultBytes, 0, numToKeep);
        }

        return resultBytes;
    }

    public static Pair<Boolean, byte[]> encryptionOracleUnknownMode(byte[] myInput) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //prepend 5-10 bytes
        Random r = new Random();
        Iterator<Integer> interator = r.ints(5, 11).iterator();
        byte[] withPrepended = ArrayUtils.addAll(Utils.randomBytes(interator.next()), myInput);

        //append 5-10 bytes
        byte[] toEncrypt = ArrayUtils.addAll(withPrepended, Utils.randomBytes(interator.next()));

        //set block size
        int blockSize = 16;

        //get key
        byte[] cipherKey = Utils.randomBytes(blockSize);

        //choose ebc or cbc
        if (r.nextInt(2) == 0) {
            //pad manually here since the ECB function doesn't do it
            return Pair.of(true, Section01.AESinECBModeWPadding(toEncrypt, cipherKey, Cipher.ENCRYPT_MODE));
        } else {
            return Pair.of(false, Section02.AESinCBCMode(toEncrypt, cipherKey, Utils.randomBytes(blockSize), Cipher.ENCRYPT_MODE));
        }
    }

    /**
     * for use in challenge 12
     * @param myInput
     * @param unknownInput
     * @param cipherKeyBytes
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     */
    private static byte[] encryptionOracleECBOnlyWithConcatenation(byte[] myInput, byte[] unknownInput, byte[] cipherKeyBytes) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        byte[] concatenatedInput = ArrayUtils.addAll(myInput, unknownInput);
        return Section01.AESinECBModeWPadding(concatenatedInput, cipherKeyBytes, Cipher.ENCRYPT_MODE);
    }

    public static byte[] breakECBEncryptionUsingOracle(byte[] unknownInput) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException {
        //get a key
        final byte[] cipherKey = Utils.randomBytes(16);

        //discover the block size of the cipher
        Integer blockSize = null;
        byte[] oracleResult = new byte[1];
        for (int i = 2; i<=128; i+=2) {
            //feed increasingly identical bytes to the oracle
            //watch for repetition
            byte[] hackerInput = new byte[i];
            Arrays.fill(hackerInput, (byte) 'A');
            oracleResult = Section02.encryptionOracleECBOnlyWithConcatenation(hackerInput, unknownInput, cipherKey);

            //see if the first i/2 bytes equals the second i/2 bytes
            if (Arrays.equals(Utils.sliceByteArray(oracleResult, 0, i/2), Utils.sliceByteArray(oracleResult, i/2, i/2))) {
                blockSize = i/2;
                break;
            }
        }

        assert blockSize != null && blockSize == 16;

        //detect that ECB is being used
        boolean ecbDetected = Section01.detectECBInCipherBytes(oracleResult, cipherKey);
        assert ecbDetected;

        //discover the first byte in the message
        //build a dictionary for bytes 0-255
        byte[] hackerInput = new byte[blockSize];
        Arrays.fill(hackerInput, (byte) 'A');
        Map<Integer, byte[]> dictionary = new HashMap<>();
        for (int i = 0; i < 256; i++) {
            hackerInput[blockSize-1] = (byte) i;
            var result = Section02.encryptionOracleECBOnlyWithConcatenation(hackerInput, new byte[0], cipherKey);
            dictionary.put(i, result);
        }

        //one byte short
        //repeat for every letter of the message
        byte[] decrypted = new byte[unknownInput.length];
        for (int i = 0; i<unknownInput.length; i++) {
            //slice off a byte of the unknown input
            hackerInput[blockSize-1] = unknownInput[i];
            //encrypt
            var encrypted = Section02.encryptionOracleECBOnlyWithConcatenation(hackerInput, new byte[0], cipherKey);
            //look up the result in the dictionary
            var dictionaryResult = dictionary.entrySet().stream().filter(e -> Arrays.equals(encrypted, e.getValue())).findAny()
                    .orElseThrow(() -> new IllegalStateException("Could not find encrypted result in dictionary"));
            decrypted[i] = dictionaryResult.getKey().byteValue();
        }

        return decrypted;
    }
}
