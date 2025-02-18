package utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@SuppressWarnings("rawtypes")
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

    static public Element H_PBC_1_1(Field G, Element m) {
        byte[] hash = HASH(m.toString());
        return G.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    static public Element H_PBC_2_1(Field G, Element m1, Element m2) {
        byte[] hash = HASH(m1.toString() + "|" + m2.toString());
        return G.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    static public Element H_PBC_3_1(Field G, Element m1, Element m2, Element m3) {
        byte[] hash = HASH(m1.toString() + "|" + m2.toString() + "|" + m3.toString());
        return G.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    static public BigInteger H_native_1_1(BigInteger m) {
        return new BigInteger(1, HASH(m.toString()));
    }

    static public BigInteger H_native_2_1(BigInteger m1, BigInteger m2) {
        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString()));
    }

//    static public BigInteger H_PBC_1_native_1(Element m1) {
//        return new BigInteger(1, HASH(m1.toString()));
//    }
//
//    static public BigInteger H_PBC_3_native_1(Element m1, Element m2, Element m3) {
//        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString() + "|" + m3.toString()));
//    }

    static public Element H_string_1_PBC_1(Field G, String m){
        byte[] hash = HASH(m);
        return G.newElementFromHash(hash, 0, hash.length).getImmutable();
    }
}
