package cryptopals.challenges.sec04;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.XOR;
import cryptopals.tool.sec04.C26_CTRAdminRightsOracle;
import cryptopals.utils.ByteArrayUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 *
 * There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.
 * Re-implement <a href="https://cryptopals.com/sets/2/challenges/16">the CBC bitflipping exercise from earlier</a>
 * {@link cryptopals.challenges.sec02.C16}
 * to use CTR mode instead of CBC mode. Inject an "admin=true" token.
 */
public class C26 {
    private final C26_CTRAdminRightsOracle oracle = new C26_CTRAdminRightsOracle();

    /**
     * verify that the implementation of the oracle we are using
     * will not allow raw injection of the string `;admin=true;`
     */
    @Test
    void theOracleEscapesRawInjection() {
        String desired = ";admin=true;A=AA";
        var enc = oracle.padAndEncrypt(desired);
        assertFalse(oracle.findAdminInCipherText(enc));
    }

    /**
     * leverage what we know about CTR to execute
     * a bit-flipping attack on the oracle
     */
    @Test
    void executeBitFlippingAttack() {
        /*
        is there a way to manipulate the encrypted message
        such that when it's decrypted, we can control the output?

        k = keystream byte (unknown)
        T = known text (7s and 9s)
        D = desired text (semicolons & equals)
        e = encrypted byte (T, but encrypted)
        o = desired encrypted output byte (D, but encrypted)

        k xor T = e
        k = e XOR T (reversible)

        k xor D = o
        (e xor T) xor D = o (substitute)
        e xor (T xor D) = o (associative)

        so ... without knowing keystream
        if we xor the known against the desired plaintext and xor that against the result
         of the first encryption, we should get the desired encrypted output byte

        this works because xor math is associative
        */

        final XOR xor = new XOR();
        String T = "7admin9true7A9AA";
        String D = ";admin=true;A=AA";
        byte[] TxorD = xor.multiByteXOR(T.getBytes(StandardCharsets.UTF_8),
                D.getBytes(StandardCharsets.UTF_8));

        //we have an intermediate that we should be able to xor against a ciphertext
        var fullFirstEncryption = oracle.padAndEncrypt("1234567890123456" + T);

        //start at position 48 because we know that the oracle supplies 2 16-byte blocks
        // and we provided a 3rd 16 byte block
        var e = ByteArrayUtil.sliceByteArray(fullFirstEncryption, 48, TxorD.length);
        var o = xor.multiByteXOR(e, TxorD);
        System.arraycopy(o, 0, fullFirstEncryption, 48, o.length);

        assertTrue(oracle.findAdminInCipherText(fullFirstEncryption));
    }
}
