package scheme.CH.CH_KEF_CZK_2004;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Chameleon Hashing without Key Exposure
 * P7. 3.3.1 The scheme
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;
        Element g;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
            g = GP.GetGElement();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(GP.G, m);
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

    private static Element getHashValue(Randomness R, PublicParam SP, Element I, Element m) {
        return SP.g.mul(I).powZn(m).mul(R.y_a).getImmutable();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        sk.x = SP.GP.GetZrElement();
        pk.y = SP.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Element I, Element m) {
        Element a = SP.GP.GetZrElement();
        R.g_a = SP.g.powZn(a).getImmutable();
        R.y_a = pk.y.powZn(a).getImmutable();
        H.h = getHashValue(R, SP, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element I, Element m) {
        return H.h.isEqual(getHashValue(R, SP, I, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element I, Element m, Element m_p) {
        Element gI = SP.g.mul(I).getImmutable();
        Element delta_m = m.sub(m_p).getImmutable();
        R_p.y_a = R.y_a.mul(gI.powZn(delta_m));
        R_p.g_a = R.g_a.mul(gI.powZn(delta_m.div(sk.x)));
    }
}
