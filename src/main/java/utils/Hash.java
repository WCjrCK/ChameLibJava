package utils;

import com.herumi.mcl.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@SuppressWarnings("rawtypes")
public class Hash {
    static public byte[] HASH(String str) {
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

    static public Element H_String_1_PBC_1(Field G, String m) {
        byte[] hash = HASH(m);
        return G.newElementFromHash(hash, 0, hash.length).getImmutable();
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

    static public BigInteger H_String_1_native_1(String m) {
        return new BigInteger(1, HASH(m));
    }

    static public BigInteger H_native_2_1(BigInteger m1, BigInteger m2) {
        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString()));
    }

    static public void H_MCL_G1_1(G1 res, String m) {
        Mcl.hashAndMapToG1(res, Hash.HASH(m));
    }

    static public void H_MCL_G2_1(G2 res, String m) {
        Mcl.hashAndMapToG2(res, Hash.HASH(m));
    }

//    static public GT H_MCL_GT_1(String m) {
//        GT res = new GT();
//        Mcl.hashAndMapToG2(res, Hash.HASH(m));
//        return res;
//    }

    static public void H_MCL_Zr_1(Fr res, String m) {
        res.setHashOf(Hash.HASH(m));
    }

//    static public BigInteger H_PBC_1_native_1(Element m1) {
//        return new BigInteger(1, HASH(m1.toString()));
//    }
//
//    static public BigInteger H_PBC_3_native_1(Element m1, Element m2, Element m3) {
//        return new BigInteger(1, HASH(m1.toString() + "|" + m2.toString() + "|" + m3.toString()));
//    }

    public static class EncText {
        public Element K;

        public EncText() {}

        public EncText(Element K) {
            this.K = K;
        }
    }

    public static class PlaText {
        public byte[] k, r;

        public PlaText() {}

        public PlaText(byte[] k, byte[] r) {
            this.k = k;
            this.r = r;
        }
    }

    public static void Encode(EncText K, Field G, PlaText P) {
        byte[] tmp = new byte[G.getLengthInBytes()];
        tmp[1] = (byte) P.k.length;
        System.arraycopy(P.k, 0, tmp, 2, P.k.length);
        tmp[G.getLengthInBytes() / 2 + 1] = (byte) P.r.length;
        System.arraycopy(P.r, 0, tmp, G.getLengthInBytes() / 2 + 2, P.r.length);
        K.K = G.newElementFromBytes(tmp).getImmutable();
    }

    public static void Decode(PlaText P, EncText K) {
        byte[] tmp = K.K.toBytes();
        int l1 = tmp[1];
        if(l1 < 0 || l1 + 2 >= tmp.length) throw new RuntimeException("Decode Failed");
        P.k = new byte[l1];
        System.arraycopy(tmp, 2, P.k, 0, l1);
        int l2 = tmp[K.K.getLengthInBytes() / 2 + 1];
        if(l2 < 0 || l2 + K.K.getLengthInBytes() / 2 + 2 >= tmp.length) throw new RuntimeException("Decode Failed");
        P.r = new byte[l2];
        System.arraycopy(tmp, K.K.getLengthInBytes() / 2 + 2, P.r, 0, l2);
    }

    public static class H_2_element {
        public Element u_1, u_2;
    }

    public static void H_2_element_String_2(H_2_element u, Field G, String m1, String m2) {
        u.u_1 = Hash.H_String_1_PBC_1(G, m1 + "|" + m2);
        u.u_2 = Hash.H_String_1_PBC_1(G, m2 + "|" + m1);
    }

    public static void H_2_element_String_3(H_2_element u, Field G, String m1, String m2, String m3) {
        u.u_1 = Hash.H_String_1_PBC_1(G, m1 + "|" + m2 + "|" + m3);
        u.u_2 = Hash.H_String_1_PBC_1(G, m3 + "|" + m2 + "|" + m1);
    }
}
