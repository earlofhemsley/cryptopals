package cryptopals.tool.sec03;

import cryptopals.tool.Chi;
import cryptopals.tool.XOR;
import cryptopals.utils.ByteArrayUtil;

import java.util.Arrays;

public class Challenge19Tool {
    //without knowing the key, can we derive the keystream?
    // ciphertext block XOR keystream block = plaintext block
    // since we have the cipher text block, we just have to figure out what to xor against these texts to make them
    // legible

    final Chi chi = new Chi();
    final XOR xor = new XOR();

    public byte[] findTheKeyStream(final byte[][] ciphertexts) {
        //inefficient, but find the longest cipher length
        int maxLen = Arrays.stream(ciphertexts)
                .map(b -> b.length)
                .max(Integer::compareTo)
                .orElseThrow();

        byte[] keyStream = new byte[maxLen];

        //get a column of letters in cipher text
        // gracefully pass by ciphertexts without letters in the column under examination
        for (int l = 0; l < keyStream.length; l++) {
            final byte[] temp = new byte[ciphertexts.length];

            int count = 0;
            for (byte[] ciphertext : ciphertexts) {
                if (l < ciphertext.length) {
                    temp[count] = ciphertext[l];
                    count++;
                }
            }
            final byte[] byteColumn = new byte[count];
            System.arraycopy(temp, 0, byteColumn, 0, count);
            keyStream[l] = determineKeyByte(byteColumn);
        }

        //manual fix for the last five characters because we inevitably got them wrong
        // just because those columns are so much shorter than the rest
        char[] turn_ = new char[] {'t', 'u', 'r', 'n', ','};
        byte[] turn_x = ByteArrayUtil.sliceEnd(ciphertexts[37], 5);
        int startPos = ciphertexts[37].length - turn_x.length;

        for (int i = 0; i < turn_.length; i++) {
            for (int j = Byte.MIN_VALUE; j < Byte.MAX_VALUE; j++) {
               if ((j ^ (int) turn_x[i]) == (int) turn_[i]) {
                   keyStream[startPos + i] = (byte) j;
               }
            }
        }

        return keyStream;
    }

    private byte determineKeyByte(final byte[] byteColumn) {
        //get the most likely first byte, but print them all

        double lowestChiScore = Double.MAX_VALUE;
        Integer winner = null;
        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; i++) {
            char[] xordFirstLetters = xor.singleKeyXOR(byteColumn, i);
            double localChi = chi.score(xordFirstLetters);
            if (localChi < lowestChiScore) {
                lowestChiScore = localChi;
                winner = i;
            }
        }

        assert winner != null;
        return (byte) winner.intValue();
    }
}
