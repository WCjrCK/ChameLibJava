package scheme.CH.CR_CH_DSS_2020;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Bringing Order to Chaos：The Case of Collision-Resistant Chameleon-Hashes
 * P25. Construction 3. Concrete instantiation of a Fully Collision-Resistant CH
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;
        public Element g;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
            g = GP.GetGElement();
        }

        private Element H(String m) {
            return Hash.H_String_1_PBC_1(GP.Zr, m);
        }

        public Element H(Element m1, Element m2, Element m3, Element m4, Element m5, Element m6, Element m7) {
            return H(String.format("(%s(%s|%s)%s)(%s|%s|%s)", m1, m2, m3, m4, m5.pow(GP.ndonr), m6.pow(GP.ndonr), m7.pow(GP.ndonr)));
        }
    }

    public static class PublicKey {
        public Element y;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class HashValue {
        public Element c_1, c_2;
    }

    public static class Randomness {
        public Element e_1, e_2, s_1, s_2;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GP.GetZrElement();
        pk.y = pp.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        Element xi, k_1;
        xi = pp.GP.GetZrElement();
        k_1 = pp.GP.GetZrElement();
        R.e_2 = pp.GP.GetZrElement();
        R.s_2 = pp.GP.GetZrElement();

        H.c_1 = pp.g.powZn(xi).getImmutable();
        H.c_2 = m.mul(pk.y.powZn(xi)).getImmutable();

        R.e_1 = pp.H(
                pk.y, H.c_1, H.c_2, m,
                pp.g.powZn(k_1), pk.y.powZn(k_1), pp.g.powZn(R.s_2).div(pk.y.powZn(R.e_2))
        ).sub(R.e_2).getImmutable();
        R.s_1 = k_1.add(R.e_1.mul(xi)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        return R.e_1.add(R.e_2).isEqual(pp.H(
                pk.y, H.c_1, H.c_2, m,
                pp.g.powZn(R.s_1).div(H.c_1.powZn(R.e_1)),
                pk.y.powZn(R.s_1).div(H.c_2.div(m).powZn(R.e_1)),
                pp.g.powZn(R.s_2).div(pk.y.powZn(R.e_2))
            )
        );
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        Element k_2;
        k_2 = pp.GP.GetZrElement();
        R_p.e_1 = pp.GP.GetZrElement();
        R_p.s_1 = pp.GP.GetZrElement();

        R_p.e_2 = pp.H(
                pk.y, H.c_1, H.c_2, m_p,
                pp.g.powZn(R_p.s_1).div(H.c_1.powZn(R_p.e_1)),
                pk.y.powZn(R_p.s_1).div(H.c_2.div(m_p).powZn(R_p.e_1)),
                pp.g.powZn(k_2)
        ).sub(R_p.e_1).getImmutable();

        R_p.s_2 = k_2.add(R_p.e_2.mul(sk.x)).getImmutable();
    }

}
