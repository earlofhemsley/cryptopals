package cryptopals.tool.sec06.c42;

import cryptopals.tool.sec05.RSA;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.HashUtil;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

@Slf4j
@UtilityClass
public class PKCS1V15RsaSignatureUtil {
    private final SHA1Digest sha1d = new SHA1Digest();

    /**
     * cryptographically sign a message using RSA + SHA1
     *
     * @param message the message
     * @param privateKey the key
     * @return a base64 encoded signature
     */
    @SneakyThrows
    public String sign(final String message, final RSA.Key privateKey) {
        //step one - get the md4 hash
        final var hash = HashUtil.getHash(message.getBytes(), sha1d);

        //step two - encode in asn.1 per the RFC
        final byte[] asn1PlusHash = ASN1Util.encodeHashToAsn1SignatureFormat(hash, OIWObjectIdentifiers.idSHA1);

        //step three - pad to the byte width of the public modulus
        byte[] result = {0, 1};
        int paddingLength = privateKey.getN().toByteArray().length - asn1PlusHash.length - 3;
        if (paddingLength < 0) {
            throw new IllegalArgumentException("The RSA Key supplied isn't long enough. Use a larger key");
        }
        for(; paddingLength > 0; paddingLength--) {
            result = ByteArrayUtil.concatenate(result, new byte[] {(byte) 0xff});
        }
        result = ByteArrayUtil.concatenate(result, new byte[] {0});
        result = ByteArrayUtil.concatenate(result, asn1PlusHash);

        //step four - encrypt with rsa
        return RSA.encrypt(result, privateKey);
    }

    /**
     * verify the signature by
     *  - decrypting using the public key
     *  - scanning the padding
     *  - decoding the asn1 to get the hash
     *  - comparing message hash to hash in signature
     * @param message message for verification
     * @param base64Signature signature encoded in base64
     * @param publicKey an RSA Key
     * @return verified as boolean
     */
    public boolean verifySignature(final String message, final String base64Signature, final RSA.Key publicKey) {
        //step four - decrypt with rsa, prepending a zero byte because RSA would have lost it
        final byte[] decrypted = ByteArrayUtil.concatenate(new byte[1], RSA.decryptToBytes(base64Signature, publicKey));

        //step three - scan the padding
        final int asn1Start = ASN1Util.findASN1Start(decrypted);

        if (asn1Start < 0) {
            log.error("Either failed decryption or malformed padding");
            return false;
        }

        //step two - decode from asn.1
        final byte[] hash;
        try {
            final int asnLength = decrypted.length - asn1Start;
            final byte[] asn = ByteArrayUtil.sliceByteArray(decrypted, asn1Start, asnLength);
            ByteArrayInputStream in = new ByteArrayInputStream(asn);
            ASN1StreamParser p = new ASN1StreamParser(in);
            var s = DERSequence.getInstance(p.readObject());

            if (s.size() != 2) {
                log.error("length of encoding is wrong. should be 2. was {}", s.size());
                return false;
            }

            final AlgorithmIdentifier oid = AlgorithmIdentifier.getInstance(s.getObjectAt(0));
            if (!oid.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1)) {
                log.error("didn't detect sha1 ({}) as the OID. Instead detected {}", OIWObjectIdentifiers.idSHA1.getId(),
                        oid.getAlgorithm().getId());
                return false;
            }

            hash = DEROctetString.getInstance(s.getObjectAt(1)).getOctets();
        } catch (IOException | IllegalArgumentException e) {
            log.error("could not parse ASN1 encoding", e);
            return false;
        }

        //step one - compare the hashes
        return Arrays.equals(HashUtil.getHash(message.getBytes(), sha1d), hash);
    }


}
