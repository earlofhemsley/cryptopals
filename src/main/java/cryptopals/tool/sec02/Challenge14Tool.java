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
        int numPrefixBlocks = breakPointIndex / blockSize + 1;

        //step three: figure out how many more bytes I need to add to this block in order to fill it
        // i do this by adding input until the block doesn't change
        Integer bufferLength = null;
        for (int i = 1; i < blockSize; i++) {
            var orig = Challenge14Oracle.speakProphecy(new byte[i - 1]);
            var origBlock = ByteArrayUtil.sliceByteArray(orig, breakPointIndex, blockSize);
            var next = Challenge14Oracle.speakProphecy(new byte[i]);
            var nextBlock = ByteArrayUtil.sliceByteArray(next, breakPointIndex, blockSize);
            if (Arrays.equals(origBlock, nextBlock)) {
                bufferLength = i - 1;
                break;
            }
        }
        if (bufferLength == null) {
            throw new CryptopalsException("could not determine buffer length");
        }

        //now I can safely sequester the prefix because i know how many bytes to add in order to make it
        // place my input at the head of a block
        // at this point, I can basically do what I did in 12, except the starting block is the
        // one after all the blocks I have filled
        final byte[] prefixBuffer = new byte[bufferLength];
        Arrays.fill(prefixBuffer, (byte) 'A');

        //now it's basically like the other one, except with an offset
        byte[] extracted = new byte[0];
        int numTotalBlocks = empty.length / blockSize;
        int numMysteryBlocks = numTotalBlocks - numPrefixBlocks;

        for (int k = 0; k < numMysteryBlocks; k++) {
            int o = k + numPrefixBlocks; // o is our offset

            byte[] block = new byte[blockSize];
            for (int i = 1; i <= blockSize; i++) {
                byte[] filler = new byte[blockSize - i];
                Arrays.fill(filler, (byte) 'A');
                filler = ByteArrayUtil.concatenate(prefixBuffer, filler);

                var fullTarget = Challenge14Oracle.speakProphecy(filler);
                var targetSegment = ByteArrayUtil.sliceByteArray(fullTarget, o * blockSize, blockSize);

                byte[] seed = ByteArrayUtil.concatenate( //blocksize + buffer -i + i -1 + kbs
                        filler, // blocksize + buffer - i
                        ByteArrayUtil.sliceByteArray(extracted, 0, k * blockSize), //what we already have - multipe of blocksize
                        ByteArrayUtil.sliceByteArray(block, 0, i - 1) // i - 1
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