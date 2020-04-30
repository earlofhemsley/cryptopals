package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.utils.CBCPaddingOracle;
import cryptopals.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Map;

public class Section03Tests {

    @Test
    public void challenge17() {
        var oracle = new CBCPaddingOracle();
        var masterMap = oracle.getAllIvecsAndStrings();
        for (Map.Entry<byte[], byte[]> pair : masterMap.entrySet()) {
            var ivec = pair.getKey();
            var encrypted = pair.getValue();

            //plaintext prime 16 = ivec prime 16 ^ intermediate16
            //plaintext prime needs to have good padding, passing whatever ivec we want into the oracle
            //so, we cycle through the last byte of ivec until we find the appropriate padding on the oracle

            byte[] decrypted = new byte[encrypted.length];
            byte[] previousCipherText = ivec;
            //separate the encrypted text into blocks
            for (int blockStart = 0; blockStart < encrypted.length; blockStart+=ivec.length) {
                var block = Utils.sliceByteArray(encrypted, blockStart, ivec.length);
                var intermediate = new byte[ivec.length];

                //roll through each byte in the intermediate from back to front
                for (int k = intermediate.length-1; k >= 0; k--) {
                    var fakeIvec = new byte[intermediate.length];

                    //make last k + 1 bytes in intermediate equal to whatever will cause them to lead out with valid padding
                    //this should only apply after we've been through parent loop 1x
                    //add one because we are gonna be looking for valid padding in space k
                    int pprime = intermediate.length - k;
                    for (int last = k + 1; last < intermediate.length; last++) {
                        //c' = i ^ p'
                        int cprime = intermediate[last] ^ pprime;
                        fakeIvec[last] = (byte) cprime;
                    }

                    for (int cprime = 0; cprime < 256; cprime++) {
                        fakeIvec[k] = (byte) cprime;
                        //see if we have good padding
                        if (oracle.validatePKCS7Padding(block, fakeIvec)) {
                            //if we do, we can find what intermediate[k] is
                            //we already know c' and p'
                            //xor to get i
                            intermediate[k] = (byte) (cprime ^ pprime);
                            break;
                        }
                    }
                }
                //by now we have the intermediate, and we have the previous block of cipher text
                //finding the original plain text is trivial
                byte[] plainText = Utils.multiByteXOR(previousCipherText, intermediate);
                System.arraycopy(plainText, 0, decrypted, blockStart, plainText.length);
                previousCipherText = block;
            }

            //see what we got
            assertTrue(oracle.decryptionIsPresentInOriginalPlainTexts(decrypted));
        }
    }
}
