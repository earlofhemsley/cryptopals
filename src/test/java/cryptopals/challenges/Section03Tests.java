package cryptopals.challenges;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.utils.CBCPaddingOracle;
import cryptopals.utils.Utils;
import cryptopals.utils.XOR;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class Section03Tests {

    @Test
    public void multipleTimes() {
        for(int i = 0; i<10; i++) {
            challenge17();
            System.out.println(String.format("Test %d successful", i));
        }
    }

    private void challenge17() {
        var oracle = new CBCPaddingOracle();
        var set = oracle.getAllIvecsAndStrings();
        final XOR xor = new XOR();
        for (Map.Entry<byte[], byte[]> pair : set.entrySet()) {
            byte[] ivec = pair.getKey();
            byte[] cipherText = pair.getValue();
            byte[] plainText = new byte[cipherText.length];
            int blockSize = ivec.length;

            for (int blockNum = 0; blockNum < cipherText.length / blockSize; blockNum++) {
                //we need a place to store our intermediate (i)
                byte[] i = new byte[blockSize];

                //then, we're going to cut off the nth block, starting at beginning
                byte[] realCipherBlock = Utils.sliceByteArray(cipherText, blockNum*blockSize, blockSize);

                //then, we're going to find the intermediate bytes
                for (int position = blockSize - 1; position >= 0; position--) {
                    findIByte(i, realCipherBlock, blockSize, position, oracle);
                }
                //at this point, we should have the whole i for the block under consideration
                //to decrypt, take the actual block and xor it against the true i to get the true plain text
                // don't worry about padding
                var plainTextBlock = xor.multiByteXOR(ivec, i);
                System.arraycopy(plainTextBlock,0, plainText, blockNum*blockSize, blockSize);
                ivec = realCipherBlock;
            }

            assertTrue(oracle.decryptionIsPresentInOriginalPlainTexts(plainText));
        }
    }

    private void findIByte(byte[] intermediate, byte[] realCipherBlock, int blockSize, int position, CBCPaddingOracle oracle) {
        //do this twice to be twice as sure
        //get the bitwise complement to be absolutely sure there's no fluke
        byte[] cPrimeA = Utils.randomBytes(blockSize);
        byte[] cPrimeB = Utils.groupByteNegation(cPrimeA);

        byte plainTextPrime = (byte) (blockSize - position);
        for (int afterPosition = position + 1; afterPosition < blockSize; afterPosition++) {
            cPrimeA[afterPosition] = cPrimeB[afterPosition] = (byte) (plainTextPrime ^ intermediate[afterPosition]);
        }

        int countOfCandidates = 0;
        for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++) {
            cPrimeA[position] = cPrimeB[position] = (byte) j;
            if (oracle.validatePKCS7Padding(realCipherBlock, cPrimeA)
                    && oracle.validatePKCS7Padding(realCipherBlock, cPrimeB)) {
                intermediate[position] = (byte) (cPrimeA[position] ^ plainTextPrime);
                countOfCandidates++;
            }
        }
        if (countOfCandidates != 1) {
            throw new CryptopalsException(countOfCandidates + " candidate byte values were found. Expected 1.");
        }
    }
}
