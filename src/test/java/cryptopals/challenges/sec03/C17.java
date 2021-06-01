package cryptopals.challenges.sec03;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.sec03.Challenge17Tool;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.tool.XOR;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CBC padding oracle
 * This is the best-known attack on modern block-cipher cryptography.
 *
 * Combine your padding code and your CBC code to write two functions.
 *
 * The first function should select at random one of the following 10 strings:
 *
 * MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
 * MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
 * MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
 * MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
 * MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
 * MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
 * MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
 * MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
 * MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
 * MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
 *
 * ... generate a random AES key (which it should save for all future encryptions),
 * pad the string out to the 16-byte AES block size and CBC-encrypt it under that key,
 * providing the caller the ciphertext and IV.
 *
 * The second function should consume the ciphertext produced by the first function, decrypt it, check its padding,
 * and return true or false depending on whether the padding is valid.
 *
 * What you're doing here.
 * This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications;
 * the second function models the server's consumption of an encrypted session token, as if it was a cookie.
 *
 * It turns out that it's possible to decrypt the ciphertexts provided by the first function.
 *
 * The decryption here depends on a side-channel leak by the decryption function.
 * The leak is the error message that the padding is valid or not.
 *
 * You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:
 *
 * The fundamental insight behind this attack is that the byte 01h is valid padding,
 * and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
 *
 * 02h in isolation is not valid padding.
 *
 * 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
 *
 * 03h 03h 03h is even less likely.
 *
 * So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.
 *
 * It is easy to get tripped up on the fact that CBC plaintexts are "padded".
 * Padding oracles have nothing to do with the actual padding on a CBC plaintext.
 * It's an attack that targets a specific bit of code that handles decryption.
 * You can mount a padding oracle on any CBC block, whether it's padded or not.
 */
public class C17 {

    @ParameterizedTest
    @ValueSource(ints = {1,2,3})
    void challenge17(final int time) {
        var oracle = new Challenge17Tool();
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
                byte[] realCipherBlock = ByteArrayUtil.sliceByteArray(cipherText, blockNum*blockSize, blockSize);

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
        System.out.printf("Test %d successful%n", time);
    }

    private void findIByte(byte[] intermediate, byte[] realCipherBlock, int blockSize, int position, Challenge17Tool oracle) {
        //do this twice to be twice as sure
        //get the bitwise complement to be absolutely sure there's no fluke
        byte[] cPrimeA = ByteArrayUtil.randomBytes(blockSize);
        byte[] cPrimeB = ByteArrayUtil.groupByteNegation(cPrimeA);

        byte plainTextPrime = (byte) (blockSize - position);
        for (int afterPosition = position + 1; afterPosition < blockSize; afterPosition++) {
            cPrimeA[afterPosition] = cPrimeB[afterPosition] = (byte) (plainTextPrime ^ intermediate[afterPosition]);
        }

        int countOfCandidates = 0;
        for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++) {
            cPrimeA[position] = cPrimeB[position] = (byte) j;
            if (oracle.askTheOracleIsPaddingValid(realCipherBlock, cPrimeA)
                    && oracle.askTheOracleIsPaddingValid(realCipherBlock, cPrimeB)) {
                intermediate[position] = (byte) (cPrimeA[position] ^ plainTextPrime);
                countOfCandidates++;
            }
        }
        if (countOfCandidates != 1) {
            throw new CryptopalsException(countOfCandidates + " candidate byte values were found. Expected 1.");
        }
    }
}
