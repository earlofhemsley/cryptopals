package cryptopals.tool.sec03;

import cryptopals.tool.AbstractFrequencyAnalyzingCTRKeyDeterminer;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Challenge20Tool extends AbstractFrequencyAnalyzingCTRKeyDeterminer {
    @Override
    public void additionalManualTweaks(final byte[][] ciphertexts, final byte[] keyStream) {
        final List<Triple<Integer, Integer, Character>> corrections = new ArrayList<>();
        corrections.add(Triple.of(26, 96, 'e'));
        corrections.add(Triple.of(26, 101, 't'));
        corrections.add(Triple.of(26, 102, 'h'));
        corrections.add(Triple.of(26, 103, 'e'));
        corrections.add(Triple.of(21, 105, 'e'));
        corrections.add(Triple.of(21, 105, 'e'));
        corrections.add(Triple.of(46, 106, ' '));
        corrections.add(Triple.of(26, 107, 'o'));
        corrections.add(Triple.of(26, 108, 'l'));
        corrections.add(Triple.of(26, 109, 'e'));
        corrections.add(Triple.of(26, 110, ' '));
        corrections.add(Triple.of(26, 111, 's'));
        corrections.add(Triple.of(26, 112, 'c'));
        corrections.add(Triple.of(26, 113, 'e'));
        corrections.add(Triple.of(26, 114, 'n'));
        corrections.add(Triple.of(26, 115, 'e'));
        corrections.add(Triple.of(26, 116, 'r'));
        corrections.add(Triple.of(26, 117, 'y'));

        for (var triple : corrections) {
            var row = triple.getLeft();
            var position = triple.getMiddle();
            var desiredChar = triple.getRight();

            for (int i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++) {
                if((i ^ (int) ciphertexts[row][position]) == (int) desiredChar) {
                    keyStream[position] = (byte) i;
                }
            }
        }
    }
}
