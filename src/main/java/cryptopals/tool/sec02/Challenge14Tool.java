package cryptopals.tool.sec02;

import cryptopals.exceptions.ECBException;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.lang3.ArrayUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Challenge14Tool {
    private final ECB ecb = new ECB(ByteArrayUtil.randomBytes(16));
    private final byte[] randomPrefix = ByteArrayUtil.randomBytes(new Random().nextInt(100));

    private byte[] encryptionOracleWrapper(byte[] hackerInput, byte[] unknownInput) throws ECBException {
        byte[] prefixPlusInput = ArrayUtils.addAll(randomPrefix, hackerInput);
        return ecb.AESWithConcatenation(prefixPlusInput, unknownInput);
    }

    public byte[] breakECBEncryptionWithPrefixUsingOracle(byte[] unknownInput) throws ECBException {
        byte[] cipherKey = ByteArrayUtil.randomBytes(16);

        // look for the first byte that changes between no hacker input and a single character of hacker input
        byte[] withouthacking = encryptionOracleWrapper(new byte[0], unknownInput);
        byte[] withHackerInput = encryptionOracleWrapper(new byte[] {(byte) 'A'}, unknownInput);

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
            withHackerInput = encryptionOracleWrapper(hackerInput, unknownInput);
        }
        final int blockSize = withHackerInput.length - withouthacking.length;
        assert indexOfFirstModifiedBlock % blockSize == 0;

        //detect ECB by submitting 3 blocks worth of repeating bytes
        byte[] repeatingBytes = new byte[3*blockSize];
        Arrays.fill(repeatingBytes, (byte) 'A');
        var oracled = encryptionOracleWrapper(repeatingBytes, unknownInput);
        boolean ecbDetected = new ECB(cipherKey).detectInCipherBytes(oracled);
        assert ecbDetected;

        //figure out how many to add until this block no longer changes
        var hackerInput = new byte[0];
        byte[] previous;
        byte[] current = ByteArrayUtil.sliceByteArray(encryptionOracleWrapper(hackerInput, unknownInput), indexOfFirstModifiedBlock, blockSize);
        int bufferSize = -1;
        do {
            bufferSize++;
            previous = current;
            hackerInput = new byte[bufferSize + 1];
            Arrays.fill(hackerInput, (byte) 'A');
            current = ByteArrayUtil.sliceByteArray(encryptionOracleWrapper(hackerInput, unknownInput), indexOfFirstModifiedBlock, blockSize);
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
            var result = encryptionOracleWrapper(targetedBytes, unknownInput);
            dictionary.put(i, ByteArrayUtil.sliceByteArray(result, indexOfFirstModifiedBlock, blockSize));
        }

        byte [] decryptedMessage = new byte[unknownInput.length];
        for (int j = 0; j < unknownInput.length; j++) {
            var messageByte = unknownInput[j];
            targetedBytes[bufferSize - 1] = messageByte;
            var result = encryptionOracleWrapper(targetedBytes, unknownInput);
            var encryptedBlock = ByteArrayUtil.sliceByteArray(result, indexOfFirstModifiedBlock, blockSize);
            int decryptedChar = dictionary.entrySet().stream().filter(e -> Arrays.equals(e.getValue(), encryptedBlock)).map(Map.Entry::getKey).findFirst().orElseThrow(() -> new AssertionError("Could not find the encrypted block"));
            decryptedMessage[j] = (byte) decryptedChar;
        }

        return decryptedMessage;
    }
}
