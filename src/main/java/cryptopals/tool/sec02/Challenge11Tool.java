package cryptopals.tool.sec02;

import cryptopals.enums.CipherMode;
import cryptopals.tool.CBC;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Random;

public class Challenge11Tool {
    public Pair<Boolean, byte[]> encryptionOracleUnknownMode(byte[] myInput) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //prepend 5-10 bytes
        Random r = new Random();
        Iterator<Integer> interator = r.ints(5, 11).iterator();
        byte[] withPrepended = ArrayUtils.addAll(ByteArrayUtil.randomBytes(interator.next()), myInput);

        //append 5-10 bytes
        byte[] toEncrypt = ArrayUtils.addAll(withPrepended, ByteArrayUtil.randomBytes(interator.next()));

        //set block size
        int blockSize = 16;

        //get key
        final byte[] cipherKeyBytes = ByteArrayUtil.randomBytes(blockSize);

        //choose ebc or cbc
        if (r.nextInt(2) == 0) {
            //pad manually here since the ECB function doesn't do it
            return Pair.of(true, new ECB(cipherKeyBytes).AESinECBModeWPadding(toEncrypt, CipherMode.ENCRYPT));
        } else {
            return Pair.of(false, new CBC(cipherKeyBytes).encryptToByteArray(toEncrypt, ByteArrayUtil.randomBytes(blockSize)));
        }
    }
}
