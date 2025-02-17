package utils;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
    static byte[] HASH(String str) {
        MessageDigest messageDigest;
        byte[] res;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes(StandardCharsets.UTF_8));
            res = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return res;
    }

    static public BigInteger H_native_1_1(BigInteger m) {
        return new BigInteger(1, HASH(m.toString()));
    }

    static public BigInteger H_native_2_1(BigInteger m1, BigInteger m2) {
        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString()));
    }

    static public BigInteger H_PBC_1_native_1(Element m1) {
        return new BigInteger(1, HASH(m1.toString()));
    }

    static public BigInteger H_PBC_3_native_1(Element m1, Element m2, Element m3) {
        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString() + "|" + m3.toString()));
    }
}
