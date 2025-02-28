package scheme.IBCH.IB_CH_KEF_CZS_2014;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * Identity-based chameleon hashing and signatures without key exposure
 * P6. 4.1. The proposed identity-based chameleon hash scheme
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Asymmetry GP;
        public Element P, P_pub;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new base.GroupParam.PBC.Asymmetry(curve, swap_G1G2);
        }

        public Element H_G1(Element m) {
            return Hash.H_PBC_1_1(GP.G1, m);
        }

        public Element H_G2(Element m) {
            return Hash.H_PBC_1_1(GP.G2, m);
        }
    }

    public static class MasterSecretKey {
        public Element x;
    }

    public static class SecretKey {
        public Element S_ID;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element r_1, r_2;
    }

    private static Element getHashValue(Randomness R, PublicParam SP, Element L, Element m) {
        return R.r_1.mul(SP.H_G1(L).powZn(m)).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        SP.P = SP.GP.GetG1Element();
        msk.x = SP.GP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.x).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.H_G2(ID).powZn(msk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element L, Element m) {
        Element a = SP.GP.GetZrElement();
        R.r_1 = SP.P.powZn(a).getImmutable();
        R.r_2 = SP.GP.pairing(SP.P_pub.powZn(a), SP.H_G2(ID));
        H.h = getHashValue(R, SP, L, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element L, Element m) {
        return H.h.isEqual(getHashValue(R, SP, L, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element L, Element m, Element m_p) {
        Element delta_m = m.sub(m_p);
        R_p.r_1 = R.r_1.mul(SP.H_G1(L).powZn(delta_m)).getImmutable();
        R_p.r_2 = R.r_2.mul(SP.GP.pairing(SP.H_G1(L), sk.S_ID).powZn(delta_m)).getImmutable();
    }
}
