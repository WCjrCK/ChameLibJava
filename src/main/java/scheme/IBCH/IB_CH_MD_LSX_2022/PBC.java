package scheme.IBCH.IB_CH_MD_LSX_2022;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P6. 4.1. The proposed identity-based chameleon hash scheme
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        Field Zr, G, GT;
        Element g, g_1, g_2, egg, eg2g;

        public Element pairing(Element g1, Element g2) {
            return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H(Element m) {
            return Hash.H_PBC_1_1(G, m);
        }

        public Element GetGElement() {
            return G.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }
    }

    public static class MasterSecretKey {
        public Element alpha, beta;
    }

    public static class SecretKey {
        public Element td_1, td_2;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element r_1, r_2;
    }

    private static Element getHashValue(Randomness R, PublicParam pp, Element ID, Element m) {
        return pp.eg2g.powZn(m).mul(pp.egg.powZn(R.r_1)).mul(pp.pairing(R.r_2, pp.g_1.div(pp.g.powZn(ID)))).getImmutable();
    }

    public void SetUp(PublicParam pp, MasterSecretKey msk, curve.PBC curve) {
        pp.pairing = Func.PairingGen(curve);
        pp.G = pp.pairing.getG1();
        pp.GT = pp.pairing.getGT();
        pp.Zr = pp.pairing.getZr();
        msk.alpha = pp.GetZrElement();
        msk.beta = pp.GetZrElement();
        pp.g = pp.GetGElement();
        pp.g_1 = pp.g.powZn(msk.alpha).getImmutable();
        pp.g_2 = pp.g.powZn(msk.beta).getImmutable();
        pp.egg = pp.pairing(pp.g, pp.g);
        pp.eg2g = pp.pairing(pp.g_2, pp.g);
    }

    public void KeyGen(SecretKey sk, PublicParam pp, MasterSecretKey msk, Element ID) {
        sk.td_1 = pp.GetZrElement();
        sk.td_2 = pp.g.powZn(msk.beta.sub(sk.td_1).div(msk.alpha.sub(ID))).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, Element ID, Element m) {
        R.r_1 = pp.GetZrElement();
        R.r_2 = pp.GetGElement();
        H.h = getHashValue(R, pp, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, Element ID, Element m) {
        return H.h.isEqual(getHashValue(R, pp, ID, m));
    }

    public void Adapt(Randomness R_p, Randomness R, SecretKey sk, Element m, Element m_p) {
        Element delta_m = m.sub(m_p).getImmutable();
        R_p.r_1 = R.r_1.add(sk.td_1.mul(delta_m));
        R_p.r_2 = R.r_2.mul(sk.td_2.powZn(delta_m)).getImmutable();
    }
}
