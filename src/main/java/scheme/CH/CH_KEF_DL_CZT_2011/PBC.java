package scheme.CH.CH_KEF_DL_CZT_2011;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Discrete logarithm based chameleon hashing and signatures withoutkey exposure
 * P4. 4.1. The proposed chameleon hash scheme
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;
        Element g;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
            g = GP.GetGElement();
        }

        public Element H(Element m1, Element m2) {
            return Hash.H_PBC_2_1(GP.G, m1, m2);
        }
    }

    public static class PublicKey {
        public Element y;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element g_a, y_a;
    }

    private static Element getHashValue(Randomness R, PublicParam SP, PublicKey pk, Element I, Element m) {
        return R.g_a.mul(SP.H(pk.y, I).powZn(m)).getImmutable();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        sk.x = SP.GP.GetZrElement();
        pk.y = SP.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Element I, Element m) {
        Element a = SP.GP.GetZrElement();
        R.g_a = SP.g.powZn(a).getImmutable();
        R.y_a = pk.y.powZn(a).getImmutable();
        H.h = getHashValue(R, SP, pk, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Element I, Element m) {
        return H.h.isEqual(getHashValue(R, SP, pk, I, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, PublicKey pk, SecretKey sk, Element I, Element m, Element m_p) {
        Element h = SP.H(pk.y, I);
        Element delta_m = m.sub(m_p).getImmutable();
        R_p.y_a = R.y_a.mul(h.powZn(delta_m.mul(sk.x)));
        R_p.g_a = R.g_a.mul(h.powZn(delta_m));
    }
}