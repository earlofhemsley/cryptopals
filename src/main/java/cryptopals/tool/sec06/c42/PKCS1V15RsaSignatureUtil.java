package cryptopals.tool.sec06.c42;

import cryptopals.tool.MD4;
import cryptopals.tool.sec05.RSA;
import cryptopals.utils.ByteArrayUtil;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

@Slf4j
@UtilityClass
public class PKCS1V15RsaSignatureUtil {

    private final MD4 md4 = new MD4();

    /**
     *
     * structure of the signature, according to RFC 2313
     *
     *     DigestInfo ::= SEQUENCE {
     *      digestAlgorithm DigestAlgorithmIdentifier,
     *      digest Digest }
     *
     *    DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     *    Digest ::= OCTET STRING
     *
     * @param message the message
     * @param privateKey the key
     * @return a base64 encoded signature
     */
    @SneakyThrows
    public String sign(final String message, final RSA.Key privateKey) {
        //step one - get the md4 hash
        final var hash = md4.getMAC(message.getBytes());

        //step two - encode in asn.1
        ASN1Sequence s1 = new DERSequence(new ASN1Encodable[] {
                //double check this format ... some places have the oid inside another sequence with the null param following the oid
                PKCSObjectIdentifiers.md4,
                //idk where to go and find that. it might be in an RFC somewhere
                new DEROctetString(hash)
        });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        s1.toASN1Primitive().encodeTo(out);
        byte[] asn1PlusHash = out.toByteArray();

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
        final int asn1Start = findASN1Start(decrypted);

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

            final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(s.getObjectAt(0));
            if (!oid.equals(PKCSObjectIdentifiers.md4)) {
                log.error("didn't detect md4 ({}) as the OID. Instead detected {}", PKCSObjectIdentifiers.md4.getId(),
                        oid.getId());
                return false;
            }

            hash = DEROctetString.getInstance(s.getObjectAt(1)).getOctets();
        } catch (IOException | IllegalArgumentException e) {
            log.error("could not parse ASN1 encoding", e);
            return false;
        }

        //step one - compare the hashes
        return Arrays.equals(md4.getMAC(message.getBytes()), hash);
    }

    /**
     * this method verifies the general format of PKCS1v1.5 padding preceding ASN.1 message information
     * 00 01 FF ... FF 00 ASN.1 HASH
     * returning the start position of the ASN.1 block
     * @param subject the subject for validation
     * @return index of the ASN.1 data, -1 if the padding is invalid
     */
    int findASN1Start(final byte[] subject) {
        //there is a minimum length in the rfc of 8 bytes
        if (subject.length < 8) {
            return -1;
        }

        //the first byte must be a 0 and the second byte must be a 1
        if ((int) subject[0] != 0 || (int) subject[1] != 1) {
            return -1;
        }

        //expect a series of unbroken 0xff bytes ...
        int index = 2;
        while (subject[index] == (byte) 0xff) {
            index++;
        }

        //followed by a 0x00 bytes
        if (subject[index] != 0) {
            return -1;
        }

        //if this is the last byte in the array, there is no next byte
        // if there is no next byte, then asn1 can't start at the next byte
        if (index >= subject.length - 1) {
            return -1;
        }

        //the asn.1 and hash come after this, so we'll return the index of that starting point
        return index + 1;
    }

}
