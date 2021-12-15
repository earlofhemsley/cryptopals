package cryptopals.tool.sec06.c42;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.ByteArrayOutputStream;

@UtilityClass
public class ASN1Util {

    @SneakyThrows
    public byte[] encodeHashToAsn1SignatureFormat(final byte[] hash, final ASN1ObjectIdentifier hashAlgo) {
        ASN1Sequence s1 = new DERSequence(new ASN1Encodable[] {
                new AlgorithmIdentifier(hashAlgo, DERNull.INSTANCE),
                new DEROctetString(hash)
        });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        s1.toASN1Primitive().encodeTo(out);
        return out.toByteArray();
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
