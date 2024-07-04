package cryptopals.tool.sec02;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class Challenge14Tool {

    public static byte[] extractTheMysteryString() {
        //step one: use the previous method thing to find the block size
        final int blockSize = Challenge12Tool.determineBlockSize(Challenge14Oracle::speakProphecy);

        //step two: find the "break point" ... the starting point of the first block that is different
        final var empty = Challenge14Oracle.speakProphecy(new byte[0]);
        final var polluted = Challenge14Oracle.speakProphecy(new byte[1]);
        Integer breakPointIndex = null;
        for (int i = 0; i < empty.length; i++) {
            if (empty[i] != polluted[i]) {
                breakPointIndex = i;
                break;
            }
        }
        if (breakPointIndex == null) {
            throw new RuntimeException("could not find break point");
        }
        log.debug("breakPointIndex: {}", breakPointIndex);
        int numPrefixBlocks = (breakPointIndex / blockSize) + 1;
        log.debug("numPrefixBlocks: {}", numPrefixBlocks);
        log.debug("num prefix bytes: {}", numPrefixBlocks * blockSize);

        //step three: figure out how many more bytes I need to add to this block in order to fill it
        // i do this by adding input until the block doesn't change
        int bufferLength = 0;
        var prev = ByteArrayUtil.sliceByteArray(Challenge14Oracle.speakProphecy(new byte[bufferLength]), breakPointIndex, blockSize);
        var next = ByteArrayUtil.sliceByteArray(Challenge14Oracle.speakProphecy(new byte[bufferLength + 1]), breakPointIndex, blockSize);
        while (bufferLength <= (blockSize * 2) && !Arrays.equals(prev, next)) {
            bufferLength++;
            prev = next;
            next = ByteArrayUtil.sliceByteArray(Challenge14Oracle.speakProphecy(new byte[bufferLength + 1]), breakPointIndex, blockSize);
        }
        log.debug("prefix length: {}", numPrefixBlocks * blockSize - bufferLength);
        log.debug("buffer length: {}", bufferLength);
        if (bufferLength == (blockSize * 2)) {
            throw new CryptopalsException("could not determine buffer length. filled two full blocks without observing change");
        }

        //now I can safely sequester the prefix because I know how many bytes to include in my hacker text
        // in order to place my input at the head of a block
        final byte[] prefixBuffer = new byte[bufferLength];

        //i need to know how many blocks of mystery text there are at the end b/c that determines when I will
        // be done interrogating the oracle
        var padded = Challenge14Oracle.speakProphecy(prefixBuffer);
        int numTotalBlocks = padded.length / blockSize;
        int numMysteryBlocks = numTotalBlocks - numPrefixBlocks;
        log.debug("numMysteryBlocks: {}", numMysteryBlocks);
        log.debug("numTotalBlocks: {}", numTotalBlocks);

        // at this point, I can basically do what I did in challenge 12, except the starting block is the
        // first one after the prefix and my buffer that fills it out all the blocks I have filled
        byte[] extracted = new byte[0];

        Map<Integer, byte[]> targets = new HashMap<>();
        for (int k = 0; k < numMysteryBlocks; k++) {
            int o = k + numPrefixBlocks; // o is our offset to the block we control

            byte[] block = new byte[blockSize];
            for (int i = 1; i <= blockSize; i++) {

                final int len = blockSize - i;
                final byte[] filler = ByteArrayUtil.concatenate(prefixBuffer, new byte[len]);

                //we can save these targets because
                // recomputing them on subsequent executions results in the same target
                // because ECB is deterministic. waste not cpu cycles
                var fullTarget = targets.computeIfAbsent(len, (l) ->
                        Challenge14Oracle.speakProphecy(filler));

                var targetSegment = ByteArrayUtil.sliceByteArray(fullTarget, o * blockSize, blockSize);

                byte[] seed = ByteArrayUtil.concatenate(
                        filler,
                        ByteArrayUtil.sliceByteArray(extracted, 0, k * blockSize),
                        ByteArrayUtil.sliceByteArray(block, 0, i - 1)
                );

                if ((seed.length - prefixBuffer.length) % blockSize != blockSize - 1) {
                    throw new CryptopalsException("the seed wasn't one byte short of a round block");
                }

                byte[] hackerInput = new byte[seed.length + 1];
                System.arraycopy(seed, 0, hackerInput, 0, seed.length);
                boolean found = false;

                for (int j = 0; j < 256; j++) {
                    hackerInput[hackerInput.length - 1] = (byte) j;
                    var result = Challenge14Oracle.speakProphecy(hackerInput);
                    var subjectSegment = ByteArrayUtil.sliceByteArray(result, o * blockSize, blockSize);
                    if (Arrays.equals(targetSegment, subjectSegment)) {
                        block[i - 1] = (byte) j;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    if (k == numMysteryBlocks - 1) {
                        block = ByteArrayUtil.sliceByteArray(block, 0, i - 2);
                        break;
                    } else {
                        throw new RuntimeException(String.format("could not find the match. k=%d, numMysteryBlocks=%d, o=%d, numTotalBlocks=%d", k, numMysteryBlocks, o, numTotalBlocks));
                    }
                }
            }
            extracted = ByteArrayUtil.concatenate(extracted, block);
        }

        return extracted;
    }
}