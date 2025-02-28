package scheme.CH.CH_FS_ECC_CCT_2024;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting
 * P6. 3.2 ECC-based Construction
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;
        public Element g;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
            g = GP.GetGElement();
        }

        public Element H(Element m) {
            return Hash.H_PBC_1_1(GP.G, m);
        }

        private Element H_p(String m) {
            return Hash.H_String_1_PBC_1(GP.Zr, m);
        }

        public Element H_p(Element m1, Element m2, Element m3, Element m4) {
            return H_p(String.format("%s|%s|%s|%s", m1, m2, m3, m4));
        }
    }

    public static class PublicKey {
        public Element g_x;
    }

    public static class SecretKey {
        public Element x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element z_1, z_2, c_1;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GP.GetZrElement();
        pk.g_x = pp.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        Element rho = pp.GP.GetZrElement();

        H.h = pp.g.powZn(rho).getImmutable();

        R.z_1 = pp.GP.GetZrElement();
        R.z_2 = pp.GP.GetZrElement();

        R.c_1 = pp.H_p(pp.g.powZn(R.z_2), pk.g_x, H.h, m);
        R.z_2 = R.z_2.sub(pp.H_p(pp.g.powZn(R.z_1).mul(pk.g_x.powZn(R.c_1)), pk.g_x, H.h, m).mul(rho)).getImmutable();

        H.h = H.h.mul(pp.H(m)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        Element y_p = H.h.div(pp.H(m));
        return R.c_1.isEqual(pp.H_p(
                pp.g.powZn(R.z_2).mul(y_p.powZn(pp.H_p(
                        pp.g.powZn(R.z_1).mul(pk.g_x.powZn(R.c_1)), pk.g_x, y_p, m
                ))), pk.g_x, y_p, m
        ));
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        Element y_p = H.h.div(pp.H(m_p));
        R_p.z_1 = pp.GP.GetZrElement();
        R_p.z_2 = pp.GP.GetZrElement();

        R_p.c_1 = pp.H_p(
                pp.g.powZn(R_p.z_2).mul(y_p.powZn(pp.H_p(
                        pp.g.powZn(R_p.z_1), pk.g_x, y_p, m_p
                ))), pk.g_x, y_p, m_p
        );

        R_p.z_1 = R_p.z_1.sub(R_p.c_1.mul(sk.x)).getImmutable();
    }
}
