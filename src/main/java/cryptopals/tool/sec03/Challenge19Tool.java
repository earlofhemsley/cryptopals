package cryptopals.tool.sec03;

import cryptopals.tool.AbstractFrequencyAnalyzingCTRKeyDeterminer;
import cryptopals.utils.ByteArrayUtil;

public class Challenge19Tool extends AbstractFrequencyAnalyzingCTRKeyDeterminer {

    @Override
    public void additionalManualTweaks(final byte[][] ciphertexts, final byte[] keyStream) {

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
    }
}
