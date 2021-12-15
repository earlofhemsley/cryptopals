package cryptopals.challenges.sec06;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.tool.sec05.RSA;
import cryptopals.tool.sec06.c42.PKCS1V15RsaSignatureUtil;
import cryptopals.tool.sec06.c42.PKCS1V15SignatureForger;
import cryptopals.utils.MathUtil;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Bleichenbacher's e=3 RSA Attack
 *
 * Crypto-tourism informational placard.
 * This attack broke Firefox's TLS certificate validation several years ago.
 * You could write a Python script to fake an RSA signature for any certificate.
 * We find new instances of it every other year or so.
 *
 * RSA with an encrypting exponent of 3 is popular, because it makes the RSA math faster.
 *
 * With e=3 RSA, encryption is just cubing a number mod the public encryption modulus:
 *
 * c = m ** 3 % n
 * e=3 is secure as long as we can make assumptions about the message blocks we're encrypting.
 * The worry with low-exponent RSA is that the message blocks we process won't be large enough
 * to wrap the modulus after being cubed. The block 00:02 (imagine sufficient zero-padding)
 * can be "encrypted" in e=3 RSA; it is simply 00:08.
 *
 * When RSA is used to sign, rather than encrypt, the operations are reversed; the verifier "decrypts" the message by
 * cubing it. This produces a "plaintext" which the verifier checks for validity.
 *
 * When you use RSA to sign a message, you supply it a block input that contains a message digest.
 * The PKCS1.5 standard formats that block as:
 *
 * 00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
 * As intended, the ffh bytes in that block expand to fill the whole block, producing a "right-justified" hash
 * (the last byte of the hash is the last byte of the message).
 *
 * There was, 7 years ago, a common implementation flaw with RSA verifiers: they'd verify signatures by "decrypting"
 * them (cubing them modulo the public exponent) and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.
 *
 * This is a bug because it implies the verifier isn't checking all the padding. If you don't check the padding,
 * you leave open the possibility that instead of hundreds of ffh bytes, you have only a few, which if you think
 * about it means there could be squizzilions of possible numbers that could produce a valid-looking signature.
 *
 * How to find such a block? Find a number that when cubed (a) doesn't wrap the modulus (thus bypassing the key
 * entirely) and (b) produces a block that starts "00h 01h ffh ... 00h ASN.1 HASH".
 *
 * There are two ways to approach this problem:
 *
 * You can work from Hal Finney's writeup, available on Google, of how Bleichenbacher explained the math
 * "so that you can do it by hand with a pencil".
 * You can implement an integer cube root in your language, format the message block you want to forge,
 * leaving sufficient trailing zeros at the end to fill with garbage, then take the cube-root of that block.
 *
 * Forge a 1024-bit RSA signature for the string "hi mom". Make sure your implementation actually accepts the signature!
 */
public class C42 {

    /**
     * verify that my signature util actually works, and that i can verify a valid signature
     */
    @Test
    void encodingDecodingTest() {
        var k = RSA.keyGen(1024);
        String msg = "hello world";
        final String sig = PKCS1V15RsaSignatureUtil.sign(msg, k.getValue());
        assertTrue(PKCS1V15RsaSignatureUtil.verifySignature(msg, sig, k.getKey()));
        assertFalse(PKCS1V15RsaSignatureUtil.verifySignature("hEllo world", sig, k.getKey()));
    }

    /**
     * I already have a cube root algorithm. I'll try that first and see if I can get it to work
     */
    @RepeatedTest(20)
    void completeTheChallenge() {
        final String message = "hi mom";
        final Pair<String, RSA.Key> forgery = PKCS1V15SignatureForger.forgeASignature(message);
        assertTrue(PKCS1V15RsaSignatureUtil.verifySignature(message, forgery.getLeft(), forgery.getRight()));
    }
}
