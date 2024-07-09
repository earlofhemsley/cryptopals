package cryptopals.tool.sec02;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.ECBDetector;
import cryptopals.utils.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class Challenge12Tool {

    private static final Logger log = LoggerFactory.getLogger(Challenge12Tool.class);

    private Challenge12Tool() {
        throw new AssertionError("cannot instantiate utility class");
    }

    public static int determineBlockSize(Function<byte[], byte[]> oracle) {
        int tripLength = 0;
        byte[] empty = oracle.apply(new byte[0]);
        byte[] filled;
        do {
            tripLength++;
            byte[] fill = new byte[tripLength];
            Arrays.fill(fill, (byte) 'A');
            filled = oracle.apply(fill);
        } while (filled.length == empty.length && tripLength < 10000);
        if (tripLength == 10000) {
            throw new RuntimeException("could not find the trip length");
        }
        return filled.length - empty.length;
    }

    /**
     * @param oracle           the oracle function of concern. takes in a byte array, returns a byte array
     * @param numPrefixBlocks  number of prefix blocks. used to determine an offset
     * @param prefixBuffer     a buffer that will push the beginning of the hacker input to the start of a block
     * @param numMysteryBlocks the number of mystery blocks you're trying to extract
     * @param blockSize        the block size
     * @return the extracted message
     */
    static byte[] performExtraction(Function<byte[], byte[]> oracle, int numPrefixBlocks, byte[] prefixBuffer, int numMysteryBlocks, int blockSize) {
        byte[] extracted = new byte[0];

        Map<Integer, byte[]> targets = new HashMap<>();
        for (int k = 0; k < numMysteryBlocks; k++) {
            int o = k + numPrefixBlocks; // o is our offset to the block we are interrogating

            byte[] block = new byte[blockSize];
            for (int i = 0; i < blockSize; i++) {

                final int len = blockSize - i - 1;
                final byte[] filler = ByteArrayUtil.concatenate(prefixBuffer, new byte[len]);

                //we can save these targets because
                // recomputing them on subsequent executions results in the same outcome
                // because ECB is deterministic. waste not cpu cycles
                var fullTarget = targets.computeIfAbsent(len, l -> oracle.apply(filler));

                var targetBlock = ByteArrayUtil.sliceByteArray(fullTarget, o * blockSize, blockSize);

                byte[] hackerInput = ByteArrayUtil.concatenate(
                        filler, //rounds out the prefix block, then gives us ( blockSize - i ) bytes in the next one
                        ByteArrayUtil.sliceByteArray(extracted, 0, extracted.length), // anything we got from previous rounds
                        ByteArrayUtil.sliceByteArray(block, 0, i), // anything we got so far on this round
                        new byte[1] //one more empty byte to round out the block
                );

                //validate that the hacker input less the prefix buffer is a multiple of the block size
                if ((hackerInput.length - prefixBuffer.length) % blockSize != 0) {
                    throw new CryptopalsException("the hackerInput didn't fill out a full block");
                }

                boolean found = false;
                for (int j = 0; j < 256; j++) {
                    hackerInput[hackerInput.length - 1] = (byte) j;
                    var result = oracle.apply(hackerInput);
                    var subjectBlock = ByteArrayUtil.sliceByteArray(result, o * blockSize, blockSize);
                    if (Arrays.equals(targetBlock, subjectBlock)) {
                        block[i] = (byte) j;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    if (k == numMysteryBlocks - 1) { //we're done
                        block = ByteArrayUtil.sliceByteArray(block, 0, i - 1);
                        break;
                    } else { // we're in trouble
                        throw new RuntimeException(String.format("could not find the match. k=%d, numMysteryBlocks=%d, offset=%d", k, numMysteryBlocks, o));
                    }
                }
            }
            extracted = ByteArrayUtil.concatenate(extracted, block);
        }

        return extracted;
    }

    public static byte[] extractTheMysteryString() {
        final int blockSize = determineBlockSize(Challenge12Oracle::speakProphecy);
        if (blockSize != 16) {
            throw new CryptopalsException("the block size is not 16");
        }

        //detect that ECB is being used
        byte[] ecbDetectionArray = new byte[blockSize * 16];
        Arrays.fill(ecbDetectionArray, (byte) 'A');
        boolean ecbDetected = ECBDetector.isECBEncrypted(ecbDetectionArray, blockSize);
        assert ecbDetected;

        byte[] empty = Challenge12Oracle.speakProphecy(new byte[0]);
        int nBlocks = empty.length / blockSize;

        return performExtraction(Challenge12Oracle::speakProphecy, 0, new byte[0], nBlocks, blockSize);
    }
}
