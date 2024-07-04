package cryptopals.tool.sec02;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.ECBDetector;
import cryptopals.utils.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
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

        byte[] extracted = new byte[0];
        byte[] empty = Challenge12Oracle.speakProphecy(new byte[0]);
        int nBlocks = empty.length / blockSize;

        for (int k = 0; k < nBlocks; k++) {
            byte[] block = new byte[blockSize];
            for (int i = 1; i <= blockSize; i++) {
                final byte[] filler = new byte[blockSize - i];
                Arrays.fill(filler, (byte) 'A');

                byte[] fullTarget = Challenge12Oracle.speakProphecy(filler);
                byte[] targetSegment = ByteArrayUtil.sliceByteArray(fullTarget, k*blockSize, blockSize);

                byte[] seed = ByteArrayUtil.concatenate(
                        filler,
                        ByteArrayUtil.sliceByteArray(extracted, 0, k*blockSize),
                        ByteArrayUtil.sliceByteArray(block, 0, i-1)
                );

                log.debug("seed (length): {} ({})", new String(seed), seed.length);
                if (seed.length % blockSize != blockSize - 1) {
                    throw new CryptopalsException("the seed wasn't one byte short of a round block");
                }

                byte[] hackerInput = new byte[seed.length + 1];
                System.arraycopy(seed, 0, hackerInput, 0, seed.length);
                boolean found = false;
                for (int j = 0; j < 256; j++) {
                    hackerInput[hackerInput.length - 1] = (byte) j;
                    var result = Challenge12Oracle.speakProphecy(hackerInput);
                    var subjectSegment = ByteArrayUtil.sliceByteArray(result, k*blockSize, blockSize);
                    if (Arrays.equals(targetSegment, subjectSegment)) {
                        block[i - 1] = (byte) j;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    if (k == nBlocks - 1) {
                        block = ByteArrayUtil.sliceByteArray(block, 0, i - 2);
                        break;
                    } else {
                        throw new RuntimeException("could not find the matching target block");
                    }
                }
            }
            extracted = ByteArrayUtil.concatenate(extracted, block);
        }

        return extracted;
    }
}
