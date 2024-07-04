package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.ECBException;

import java.util.Arrays;

public class ECBDetector {
    private ECBDetector() {
       throw new Error("Do not instantiate");
    }

    /**
     * given a series of messages, detect which of the messages was decrypted in ECB mode.
     *
     * this is the solution to challenge eight
     * @param cipherBytes encrypted message bytes
     * @return true if found, false otherwise
     * @throws ECBException if a problem with ECB operation surfaces
     */
    public static boolean isECBEncrypted(byte[] cipherBytes, int keySize){
        if (cipherBytes.length % keySize != 0) {
            throw new ECBException("message length must be a multiple of the cipher key length, which is " + keySize);
        }

        //decrypt
        byte[] decryptedCipherBytes = new ECB(new byte[keySize]).AES128(cipherBytes, CipherMode.DECRYPT);

        int loopIterations = decryptedCipherBytes.length/keySize;

        //break the decrypted text into 16-byte blocks
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
