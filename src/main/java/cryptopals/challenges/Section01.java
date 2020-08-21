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

}
