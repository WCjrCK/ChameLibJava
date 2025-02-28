package scheme.IBCH.IB_CH_ZSS_S1_2003;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.1 Scheme 1
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Asymmetry GP;
        Element P, P_pub;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new base.GroupParam.PBC.Asymmetry(curve, swap_G1G2);
        }

        public Element H0(Element m) {
            return Hash.H_PBC_1_1(GP.G1, m);
        }

        public Element H1(Element m) {
            return Hash.H_PBC_1_1(GP.Zr, m);
        }
    }

    public static class MasterSecretKey {
        public Element s;
    }

    public static class SecretKey {
        public Element S_ID;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element R;
    }

    private static Element getHashValue(Randomness R, PublicParam SP, Element ID, Element m) {
        return SP.GP.pairing(R.R, SP.P).mul(SP.GP.pairing(SP.H0(ID).powZn(SP.H1(m)), SP.P_pub)).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        SP.P = SP.GP.GetG2Element();
        msk.s = SP.GP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.s).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.H0(ID).powZn(msk.s).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        R.R = SP.GP.GetG1Element();
        H.h = getHashValue(R, SP, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        return H.h.isEqual(getHashValue(R, SP, ID, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element m, Element m_p) {
        R_p.R = R.R.mul(sk.S_ID.powZn(SP.H1(m).sub(SP.H1(m_p)))).getImmutable();
    }
}
