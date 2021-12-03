package cryptopals.tool.sec06.c42;

import lombok.experimental.UtilityClass;

@UtilityClass
public class PKCS1v15Validator {

    /**
     * this method verifies the general format of PKCS1v1.5 padding preceding ASN.1 message information
     * 00 01 FF ... FF 00 ASN.1 HASH
     * returning the start position of the ASN.1 block
     * @param subject the subject for validation
     * @return index of the ASN.1 data, -1 if the padding is invalid
     */
    public int findAsnStartingIndex(final byte[] subject) {
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
