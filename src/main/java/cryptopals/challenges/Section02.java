package cryptopals.challenges;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.tool.XOR;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static cryptopals.utils.PKCS7Util.applyPadding;

public class Section02 {

    public static byte[] AESinCBCMode(byte[] textBytes, final byte[] cipherKeyBytes, final byte[] iv, CipherMode cipherMode)  {
        final ECB ecb = new ECB(cipherKeyBytes);
        if (cipherMode == null) {
            throw new IllegalArgumentException("Cipher mode is required");
        }
        //block size will be the size of the cipher key
        //make sure the iv and the cipherkey are the same size
        if (cipherKeyBytes.length != iv.length) {
            throw new IllegalArgumentException("cipher key and init vector must be the same length");
        }

        if (textBytes.length % cipherKeyBytes.length != 0) {
            throw new IllegalArgumentException("text length must be a multiple of the block size. Did you pad your message?");
        }

        final XOR xor = new XOR();
        byte[] resultBytes = new byte[textBytes.length];
        byte[] previousBlock = iv;

        for (int n = 0; n < textBytes.length; n+=iv.length) {
            //get the nth block
            byte[] nthBlock = ByteArrayUtil.sliceByteArray(textBytes, n, iv.length);

            byte[] currentBlock;
            try {
                switch (cipherMode) {
                    case ENCRYPT:
                        byte[] xorNthBlock = xor.multiByteXOR(nthBlock, previousBlock);
                        currentBlock = ecb.AESInECBMode(xorNthBlock, cipherMode);
                        previousBlock = currentBlock;
                        break;
                    case DECRYPT:
                        byte[] decNthBlock = ecb.AESInECBMode(nthBlock, cipherMode);
                        currentBlock = xor.multiByteXOR(decNthBlock, previousBlock);
                        previousBlock = nthBlock;
                        break;
                    default:
                        throw new IllegalArgumentException("illegal cipher mode");
                }
            } catch (Exception e) {
                throw new CryptopalsException("could not execute the desired operation", e);
            }

            System.arraycopy(currentBlock, 0, resultBytes, n, iv.length);
        }

        return resultBytes;
    }

    public static Pair<Boolean, byte[]> encryptionOracleUnknownMode(byte[] myInput) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //prepend 5-10 bytes
        Random r = new Random();
        Iterator<Integer> interator = r.ints(5, 11).iterator();
        byte[] withPrepended = ArrayUtils.addAll(ByteArrayUtil.randomBytes(interator.next()), myInput);

        //append 5-10 bytes
        byte[] toEncrypt = ArrayUtils.addAll(withPrepended, ByteArrayUtil.randomBytes(interator.next()));

        //set block size
        int blockSize = 16;

        //get key
        final ECB ecb = new ECB(ByteArrayUtil.randomBytes(blockSize));

        //choose ebc or cbc
        if (r.nextInt(2) == 0) {
            //pad manually here since the ECB function doesn't do it
            return Pair.of(true, ecb.AESinECBModeWPadding(toEncrypt, CipherMode.ENCRYPT));
        } else {
            return Pair.of(false, AESinCBCMode(applyPadding(toEncrypt, blockSize), ecb.getCipherKeyBytes(), ByteArrayUtil.randomBytes(blockSize), CipherMode.ENCRYPT));
        }
    }

    /**
     * for use in challenge 12
     * @param ecb
     * @param myInput
     * @param unknownInput
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     */
    private static byte[] encryptionOracleECBOnlyWithConcatenation(final ECB ecb, byte[] myInput, byte[] unknownInput) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        byte[] concatenatedInput = ArrayUtils.addAll(myInput, unknownInput);
        return ecb.AESinECBModeWPadding(concatenatedInput, CipherMode.ENCRYPT);
    }

    public static byte[] breakECBEncryptionUsingOracle(byte[] unknownInput) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException {
        //get a key
        final ECB ecb = new ECB(ByteArrayUtil.randomBytes(16));

        //discover the block size of the cipher
        Integer blockSize = null;
        byte[] oracleResult = new byte[1];
        for (int i = 2; i<=128; i+=2) {
            //feed increasingly identical bytes to the oracle
            //watch for repetition
            byte[] hackerInput = new byte[i];
            Arrays.fill(hackerInput, (byte) 'A');
            oracleResult = encryptionOracleECBOnlyWithConcatenation(ecb, hackerInput, unknownInput);

            //see if the first i/2 bytes equals the second i/2 bytes
            if (Arrays.equals(ByteArrayUtil.sliceByteArray(oracleResult, 0, i/2), ByteArrayUtil.sliceByteArray(oracleResult, i/2, i/2))) {
                blockSize = i/2;
                break;
            }
        }

        assert blockSize != null && blockSize == 16;

        //detect that ECB is being used
        boolean ecbDetected = ecb.detectECBInCipherBytes(oracleResult);
        assert ecbDetected;

        //discover the first byte in the message
        //build a dictionary for bytes 0-255
        byte[] hackerInput = new byte[blockSize];
        Arrays.fill(hackerInput, (byte) 'A');
        Map<Integer, byte[]> dictionary = new HashMap<>();
        for (int i = 0; i < 256; i++) {
            hackerInput[blockSize-1] = (byte) i;
            var result = encryptionOracleECBOnlyWithConcatenation(ecb, hackerInput, new byte[0]);
            dictionary.put(i, result);
        }

        //one byte short
        //repeat for every letter of the message
        byte[] decrypted = new byte[unknownInput.length];
        for (int i = 0; i<unknownInput.length; i++) {
            //slice off a byte of the unknown input
            hackerInput[blockSize-1] = unknownInput[i];
            //encrypt
            var encrypted = encryptionOracleECBOnlyWithConcatenation(ecb, hackerInput, new byte[0]);
            //look up the result in the dictionary
            var dictionaryResult = dictionary.entrySet().stream().filter(e -> Arrays.equals(encrypted, e.getValue())).findAny()
                    .orElseThrow(() -> new IllegalStateException("Could not find encrypted result in dictionary"));
            decrypted[i] = dictionaryResult.getKey().byteValue();
        }

        return decrypted;
    }

    public static Map<String, Object> keyValueParsing(String theString) {
        return keyValueParsing(theString, '&');
    }

    public static Map<String, Object> keyValueParsing(String theString, char delimiter) {
        String[] pairs = theString.split(String.valueOf(delimiter));
        Map<String, Object> retval = new HashMap<>();
        for (String pair : pairs) {
            if(!pair.contains("=")) {
                continue;
            }
            String[] kv = pair.split("=");
            retval.put(kv[0], kv[1]);
        }

        return retval;
    }

    public static String profileFor(String userEmail) {
        //encode metachars
        Map<String, Object> upMap = new LinkedHashMap<>();
        userEmail = userEmail.replace("=","");
        userEmail = userEmail.replace("&","");
        upMap.put("email", userEmail);
        upMap.put("uid", 10);
        upMap.put("role", "user");

        return upMap.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue().toString()).collect(Collectors.joining("&"));
    }

    private static byte[] challenge13key = ByteArrayUtil.randomBytes(16);

    public static byte[] encryptProfile(String profile) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        return new ECB(challenge13key).AESinECBModeWPadding(profile.getBytes(), CipherMode.ENCRYPT);
    }

    public static Map<String, Object> decryptAndParse(byte[] encryptedProfile) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        return keyValueParsing(new String(new ECB(challenge13key).AESinECBModeWPadding(encryptedProfile, CipherMode.DECRYPT)));
    }

    private static final byte[] randomPrefix = ByteArrayUtil.randomBytes(new Random().nextInt(100));
    private static byte[] encryptionOracleECBWithPrefix(byte[] myInput, byte[] unknownInput, byte[] cipherKeyBytes) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] prefixPlusInput = ArrayUtils.addAll(randomPrefix, myInput);
        return encryptionOracleECBOnlyWithConcatenation(new ECB(cipherKeyBytes), prefixPlusInput, unknownInput);
    }

    public static byte[] breakECBEncryptionWithPrefixUsingOracle(byte[] unknownInput) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, DecoderException {
        byte[] cipherKey = ByteArrayUtil.randomBytes(16);

        // look for the first byte that changes between no hacker input and a single character of hacker input
        byte[] withouthacking = encryptionOracleECBWithPrefix(new byte[0], unknownInput, cipherKey);
        byte[] withHackerInput = encryptionOracleECBWithPrefix(new byte[] {(byte) 'A'}, unknownInput, cipherKey);

        //find index of modified cipher block
        Integer indexOfFirstModifiedBlock = null;
        for(int index = 0; index < withouthacking.length; index++) {
            if (withouthacking[index] != withHackerInput[index]) {
                indexOfFirstModifiedBlock = index;
                break;
            }
        }
        assert indexOfFirstModifiedBlock != null;

        //find block size by continuing to add input until the size of the message changes.
        // Then subtract the two lengths. that's the block size
        for (int n = 1; withHackerInput.length == withouthacking.length; n++) {
            byte[] hackerInput = new byte[n];
            Arrays.fill(hackerInput, (byte) 'A');
            withHackerInput = encryptionOracleECBWithPrefix(hackerInput, unknownInput, cipherKey);
        }
        final int blockSize = withHackerInput.length - withouthacking.length;
        assert indexOfFirstModifiedBlock % blockSize == 0;

        //detect ECB by submitting 3 blocks worth of repeating bytes
        byte[] repeatingBytes = new byte[3*blockSize];
        Arrays.fill(repeatingBytes, (byte) 'A');
        var oracled = encryptionOracleECBWithPrefix(repeatingBytes, unknownInput, cipherKey);
        boolean ecbDetected = new ECB(cipherKey).detectECBInCipherBytes(oracled);
        assert ecbDetected;

        //figure out how many to add until this block no longer changes
        var hackerInput = new byte[0];
        byte[] previous;
        byte[] current = ByteArrayUtil.sliceByteArray(encryptionOracleECBWithPrefix(hackerInput, unknownInput, cipherKey), indexOfFirstModifiedBlock, blockSize);
        int bufferSize = -1;
        do {
            bufferSize++;
            previous = current;
            hackerInput = new byte[bufferSize + 1];
            Arrays.fill(hackerInput, (byte) 'A');
            current = ByteArrayUtil.sliceByteArray(encryptionOracleECBWithPrefix(hackerInput, unknownInput, cipherKey), indexOfFirstModifiedBlock, blockSize);
        } while (!Arrays.equals(previous, current));
        assert (randomPrefix.length + bufferSize) % blockSize == 0;

        //now that we know what block changes, how many bytes to add to fill that block, and the block size,
        // we can decrypt the message

        //build a dictionary
        byte[] targetedBytes = new byte[bufferSize];
        Arrays.fill(targetedBytes, (byte) 'A');
        var dictionary = new HashMap<Integer, byte[]>();
        for (int i = 0; i < 255; i++) {
            byte b = (byte) i;
            targetedBytes[targetedBytes.length - 1] = b;
            var result = encryptionOracleECBWithPrefix(targetedBytes, unknownInput, cipherKey);
            dictionary.put(i, ByteArrayUtil.sliceByteArray(result, indexOfFirstModifiedBlock, blockSize));
        }

        byte [] decryptedMessage = new byte[unknownInput.length];
        for (int j = 0; j < unknownInput.length; j++) {
            var messageByte = unknownInput[j];
            targetedBytes[bufferSize - 1] = messageByte;
            var result = encryptionOracleECBWithPrefix(targetedBytes, unknownInput, cipherKey);
            var encryptedBlock = ByteArrayUtil.sliceByteArray(result, indexOfFirstModifiedBlock, blockSize);
            int decryptedChar = dictionary.entrySet().stream().filter(e -> Arrays.equals(e.getValue(), encryptedBlock)).map(Map.Entry::getKey).findFirst().orElseThrow(() -> new AssertionError("Could not find the encrypted block"));
            decryptedMessage[j] = (byte) decryptedChar;
        }

        return decryptedMessage;
    }

}
