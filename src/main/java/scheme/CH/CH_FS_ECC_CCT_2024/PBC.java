package scheme.CH.CH_FS_ECC_CCT_2024;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

/*
 * Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting
 * P6. 3.2 ECC-based Construction
 */

@SuppressWarnings("rawtypes")
public class PBC {public static class PublicParam {
    Field Zr, G;
    Element g;

    public Element H(Element m) {
        return Hash.H_PBC_1_1(G, m);
    }

    private Element H_p(String m) {
        return Hash.H_String_1_PBC_1(Zr, m);
    }

    public Element H_p(Element m1, Element m2, Element m3, Element m4) {
        return H_p(String.format("%s|%s|%s|%s", m1, m2, m3, m4));
    }

    public Element GetGElement() {
        return G.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
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

    public void SetUp(PublicParam pp, curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        pp.G = Func.GetPBCField(pairing, group);
        pp.Zr = pairing.getZr();
        pp.g = pp.GetGElement();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GetZrElement();
        pk.g_x = pp.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        Element rho = pp.GetZrElement();

        H.h = pp.g.powZn(rho).mul(pp.H(m)).getImmutable();


        Element t_2;
        t_2 = pp.GetZrElement();
        R.z_1 = pp.GetZrElement();

        R.c_1 = pp.H_p(pp.g.powZn(t_2), pk.g_x, pp.g.powZn(rho), m);
        R.z_2 = t_2.sub(pp.H_p(pp.g.powZn(R.z_1).mul(pk.g_x.powZn(R.c_1)), pk.g_x, pp.g.powZn(rho), m).mul(rho)).getImmutable();
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
        Element t_1_p = pp.GetZrElement();
        R_p.z_2 = pp.GetZrElement();

        R_p.c_1 = pp.H_p(
                pp.g.powZn(R_p.z_2).mul(y_p.powZn(pp.H_p(
                        pp.g.powZn(t_1_p), pk.g_x, y_p, m_p
                ))), pk.g_x, y_p, m_p
        );

        R_p.z_1 = t_1_p.sub(R_p.c_1.mul(sk.x)).getImmutable();
    }
}
