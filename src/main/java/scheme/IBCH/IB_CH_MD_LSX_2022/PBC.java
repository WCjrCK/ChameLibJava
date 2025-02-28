package scheme.IBCH.IB_CH_MD_LSX_2022;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Efficient Identity-Based Chameleon Hash For Mobile Devices
 * P2. 3. PROPOSED EFFICIENT IB-CH
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Symmetry GP;
        Element g, g_1, g_2, egg, eg2g;

        public PublicParam(curve.PBC curve) {
            GP = new base.GroupParam.PBC.Symmetry(curve);
        }

        public Element H(Element m) {
            return Hash.H_PBC_1_1(GP.G, m);
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
        return pp.eg2g.powZn(m).mul(pp.egg.powZn(R.r_1)).mul(pp.GP.pairing(R.r_2, pp.g_1.div(pp.g.powZn(ID)))).getImmutable();
    }

    public void SetUp(PublicParam pp, MasterSecretKey msk) {
        msk.alpha = pp.GP.GetZrElement();
        msk.beta = pp.GP.GetZrElement();
        pp.g = pp.GP.GetGElement();
        pp.g_1 = pp.g.powZn(msk.alpha).getImmutable();
        pp.g_2 = pp.g.powZn(msk.beta).getImmutable();
        pp.egg = pp.GP.pairing(pp.g, pp.g);
        pp.eg2g = pp.GP.pairing(pp.g_2, pp.g);
    }

    public void KeyGen(SecretKey sk, PublicParam pp, MasterSecretKey msk, Element ID) {
        sk.td_1 = pp.GP.GetZrElement();
        sk.td_2 = pp.g.powZn(msk.beta.sub(sk.td_1).div(msk.alpha.sub(ID))).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, Element ID, Element m) {
        R.r_1 = pp.GP.GetZrElement();
        R.r_2 = pp.GP.GetGElement();
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
