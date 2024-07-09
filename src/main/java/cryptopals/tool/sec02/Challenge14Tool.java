package cryptopals.tool.sec02;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

@Slf4j
public class Challenge14Tool {

    public static byte[] extractTheMysteryString() {
        //step one: use the previous method thing to find the block size
        final int blockSize = Challenge12Tool.determineBlockSize(Challenge14Oracle::speakProphecy);

        //step two: find the "break point" ... the starting point of the first block that is different
        // this block is where the prefix _ends_
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

        //step three: figure out how many more bytes I need to add to this block where the prefix ends
        // in order to fill it. i do this by adding input until the block doesn't change anymore.
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

        //I need to know how many blocks of mystery text there are at the end b/c that determines when I will
        // be done interrogating the oracle
        var padded = Challenge14Oracle.speakProphecy(prefixBuffer);
        int numTotalBlocks = padded.length / blockSize;
        int numMysteryBlocks = numTotalBlocks - numPrefixBlocks;
        log.debug("numMysteryBlocks: {}", numMysteryBlocks);
        log.debug("numTotalBlocks: {}", numTotalBlocks);

        return Challenge12Tool.performExtraction(Challenge14Oracle::speakProphecy, numPrefixBlocks, prefixBuffer, numMysteryBlocks, blockSize);
    }
}