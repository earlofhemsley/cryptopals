package cryptopals.tool.sec05.c40;

import cryptopals.tool.sec05.RSA;
import cryptopals.utils.MathUtil;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;

@UtilityClass
public class RSACubeRooter {

    /**
     * use the Chinese Remainder Theorem to decrypt an RSA encryption from
     * 3 cipher texts and their keys
     * @return the decrypted text
     */
    public String root(Pair<String, RSA.Key> zero, Pair<String, RSA.Key> one, Pair<String, RSA.Key> two) {
        //unpack
        final BigInteger c0 = new BigInteger(1, Base64.decode(zero.getLeft()));
        final BigInteger c1 = new BigInteger(1, Base64.decode(one.getLeft()));
        final BigInteger c2 = new BigInteger(1, Base64.decode(two.getLeft()));

        final BigInteger n0 = zero.getValue().getN();
        final BigInteger n1 = one.getValue().getN();
        final BigInteger n2 = two.getValue().getN();

        //find the important elements of the equation
        final BigInteger n012 = n0.multiply(n1).multiply(n2);
        final BigInteger ms0 = n012.divide(n0);
        final BigInteger ms1 = n012.divide(n1);
        final BigInteger ms2 = n012.divide(n2);

        //find each portion of the equation
        final BigInteger r0 = c0.multiply(ms0).multiply(MathUtil.invMod(ms0, n0));
        final BigInteger r1 = c1.multiply(ms1).multiply(MathUtil.invMod(ms1, n1));
        final BigInteger r2 = c2.multiply(ms2).multiply(MathUtil.invMod(ms2, n2));

        //find r
        BigInteger r = r0.add(r1).add(r2).mod(n012);

        BigInteger d = MathUtil.iroot(BigInteger.valueOf(3), r);

        return new String(d.toByteArray());
    }
}
