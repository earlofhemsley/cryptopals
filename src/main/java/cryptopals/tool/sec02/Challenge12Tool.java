package cryptopals.tool.sec02;

import cryptopals.exceptions.ECBException;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Challenge12Tool {

    private final ECB ecb = new ECB(ByteArrayUtil.randomBytes(16));

    public byte[] breakECBEncryption(byte[] unknownInput) throws ECBException {

        //discover the block size of the cipher
        Integer blockSize = null;
        byte[] oracleResult = new byte[1];
        for (int i = 2; i<=128; i+=2) {
            //feed increasingly identical bytes to the oracle
            //watch for repetition
            byte[] hackerInput = new byte[i];
            Arrays.fill(hackerInput, (byte) 'A');
            oracleResult = ecb.AESWithConcatenation(hackerInput, unknownInput);

            //see if the first i/2 bytes equals the second i/2 bytes
            if (Arrays.equals(ByteArrayUtil.sliceByteArray(oracleResult, 0, i/2), ByteArrayUtil.sliceByteArray(oracleResult, i/2, i/2))) {
                blockSize = i/2;
                break;
            }
        }

        assert blockSize != null && blockSize == 16;

        //detect that ECB is being used
        boolean ecbDetected = ecb.detectInCipherBytes(oracleResult);
        assert ecbDetected;

        //discover the first byte in the message
        //build a dictionary for bytes 0-255
        byte[] hackerInput = new byte[blockSize];
        Arrays.fill(hackerInput, (byte) 'A');
        Map<Integer, byte[]> dictionary = new HashMap<>();
        for (int i = 0; i < 256; i++) {
            hackerInput[blockSize-1] = (byte) i;
            var result = ecb.AESWithConcatenation(hackerInput, new byte[0]);
            dictionary.put(i, result);
        }

        //one byte short
        //repeat for every letter of the message
        byte[] decrypted = new byte[unknownInput.length];
        for (int i = 0; i<unknownInput.length; i++) {
            //slice off a byte of the unknown input
            hackerInput[blockSize-1] = unknownInput[i];
            //encrypt
            var encrypted = ecb.AESWithConcatenation(hackerInput, new byte[0]);
            //look up the result in the dictionary
            var dictionaryResult = dictionary.entrySet().stream().filter(e -> Arrays.equals(encrypted, e.getValue())).findAny()
                    .orElseThrow(() -> new IllegalStateException("Could not find encrypted result in dictionary"));
            decrypted[i] = dictionaryResult.getKey().byteValue();
        }

        return decrypted;
    }
}
