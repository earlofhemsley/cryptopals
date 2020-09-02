package cryptopals.challenges;

import cryptopals.enums.CipherMode;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

public class Section02 {
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
        return new ECB(cipherKeyBytes).AESinEBCModeWConcatenation(prefixPlusInput, unknownInput);
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
