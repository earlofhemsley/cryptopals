package cryptopals.tool.sec06.c42;

import cryptopals.tool.MD4;
import cryptopals.tool.SHA1;
import cryptopals.tool.sec05.RSA;
import cryptopals.utils.ByteArrayUtil;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.ByteArrayOutputStream;

@UtilityClass
public class PKCS1V15RsaSignatureUtil {

    private final MD4 md4 = new MD4();

    /**
     * structure of the signature, according to RFC 2313
     *
     *     DigestInfo ::= SEQUENCE {
     *      digestAlgorithm DigestAlgorithmIdentifier,
     *      digest Digest }
     *
     *    DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     *    Digest ::= OCTET STRING
     *
     * @param message
     * @param privateKey
     * @return
     */
    @SneakyThrows
    public String sign(final String message, final RSA.Key privateKey) {
        //step one - get the md4 hash
        //step two - encode in asn.1
        //step three - pad to the byte width of the public modulus
        //step four - encrypt with rsa
        final var hash = md4.getMAC(message.getBytes());
        ASN1Sequence s1 = new DERSequence(new ASN1Encodable[] {
                //double check this format ... some places have the oid inside another sequence with the null param following the oid
                PKCSObjectIdentifiers.md4,
                //idk where to go and find that. it might be in an RFC somewhere
                new DEROctetString(hash)
        });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        s1.toASN1Primitive().encodeTo(out);
        byte[] asn1PlusHash = out.toByteArray();
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
        return RSA.encrypt(result, privateKey);
    }


    /**
     * this method verifies the general format of PKCS1v1.5 padding preceding ASN.1 message information
     * 00 01 FF ... FF 00 ASN.1 HASH
     * returning the start position of the ASN.1 block
     * @param subject the subject for validation
     * @return index of the ASN.1 data, -1 if the padding is invalid
     */
    public int verifySignature(final byte[] subject) {
        //length couldn't possibly be valid for a short subject
        if (subject.length < 5) {
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

        //followed by a pair of 0x00 bytes
        if (subject[index] != 0) {
            return -1;
        }

        //the asn.1 and hash come after this, so we'll return the index of that starting point
        return index + 1;
    }

}
