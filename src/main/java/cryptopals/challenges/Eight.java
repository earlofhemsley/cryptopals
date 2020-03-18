package cryptopals.challenges;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Eight {
    private static final byte[] cipherKeyBytes = "1234567890123456".getBytes();
    public static int detectECBInCipherText(List<String> cipherTexts) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");

        var possibleRows = new HashSet<Integer>();
        for (int row = 0; row < cipherTexts.size(); row++) {
            //hex decode
            byte[] decodedCipherText = Hex.decodeHex(cipherTexts.get(row));

            //decrypt
            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
            byte[] decryptedCipherBytes = cipher.doFinal(decodedCipherText);

            int loopIterations = decryptedCipherBytes.length/16;

            //break the decoded text into 16-byte blocks
            byte[][] decryptedBlocks = new byte[loopIterations][16];
            for (int i = 0; i < loopIterations; i++) {
                decryptedBlocks[i] = Arrays.copyOfRange(decryptedCipherBytes, i*16, (i*16)+16);
                //go back through what was already decrypted and check for equality
                for(int j = 0; j < i; j++) {
                    if (Arrays.equals(decryptedBlocks[j], decryptedBlocks[i])) {
                        //if we found two bytes that decrypted out the same in this row,
                        // then this is a row that was encrypted with ECB
                        possibleRows.add(row);
                    }
                }
            }
        }
        return possibleRows.size() > 0 ? possibleRows.iterator().next() : -1;
    }
}
