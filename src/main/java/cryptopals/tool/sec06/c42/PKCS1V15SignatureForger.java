package cryptopals.tool.sec06.c42;

import static java.math.BigInteger.ONE;

import cryptopals.tool.SHA1;
import cryptopals.tool.sec05.RSA;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import cryptopals.utils.MathUtil;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/**
 * This is an RSA Signature verifier. It validates RSA Signatures.
 * It's also extremely flawed. It doesn't validate right justification
 * of the message
 */
@UtilityClass
public class PKCS1V15SignatureForger {
    private final SHA1Digest digest = new SHA1Digest();

    /**
     * force a signature that takes advantage of bleichenbacher's RSA signature forgery exploit
     * this exploit requires a public lock of e=3.
     *
     * @param message
     * @return
     */
    @SneakyThrows
    public Pair<String, RSA.Key> forgeASignature(final String message) {
        final var keypair = RSA.keyGen(1024, 3);

        final var hash = HashUtil.getHash(message.getBytes(), digest);

        //step two - encode in asn.1 per the RFC
        byte[] asn1PlusHash = ASN1Util.encodeHashToAsn1SignatureFormat(hash, OIWObjectIdentifiers.idSHA1);

        //start building a forgery
        //do the bare minimum as far as leading padding goes ... eight bytes only
        byte[] forgery = ByteArrayUtil.concatenate(
                new byte[] {0, 1, -1, -1, -1, -1, -1, -1, -1, -1, 0},
                asn1PlusHash
        );

        //get the byte length of the public n. this will need to be filled with empty bytes
        // for a cube root
        int requiredLen = keypair.getKey().getN().toByteArray().length - forgery.length;

        //fill up the remaining width (length of n minus what we already have) with empty bytes
        // this will help the cube root
        forgery = ByteArrayUtil.concatenate(forgery, new byte[requiredLen]);

        //convert to big int
        final BigInteger forgeryAsInt = new BigInteger(1, forgery);

        //get the cube root and add one.
        // by adding one, we guarantee that the upper bits of the eventual cube will remain
        // untouched while allowing the garbage bytes at the bottom to be filled with spillover.
        // when this is cubed, the actual result will be greater than our forgery
        // but as we're taking advantage of the non-enforced right padding
        // we don't care what happens after the hash. we can allow the cube to be greater than
        // our forgery as long as the most significant bits do not get altered, which
        // because this is such a large number, they won't.
        final BigInteger cubeRoot = MathUtil.iroot(keypair.getKey().getK(), forgeryAsInt).add(ONE);

        return Pair.of(Base64.encodeBase64String(cubeRoot.toByteArray()), keypair.getLeft());
    }
}
