package utils;

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

    static public BigInteger H(BigInteger m1, BigInteger m2) {
        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString()));
    }
}
