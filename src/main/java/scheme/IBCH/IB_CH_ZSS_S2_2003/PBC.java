package scheme.IBCH.IB_CH_ZSS_S2_2003;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.2 Scheme 2
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Symmetry GP;
        Element P, P_pub;

        public PublicParam(curve.PBC curve) {
            GP = new base.GroupParam.PBC.Symmetry(curve);
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
        return SP.GP.pairing(SP.P, SP.P).mul(SP.GP.pairing(SP.P.powZn(SP.H1(ID)).mul(SP.P_pub), R.R)).powZn(SP.H1(m)).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        SP.P = SP.GP.GetGElement();
        msk.s = SP.GP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.s).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.P.powZn(msk.s.add(SP.H1(ID)).invert()).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        R.R = SP.GP.GetGElement();
        H.h = getHashValue(R, SP, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        return H.h.isEqual(getHashValue(R, SP, ID, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element m, Element m_p) {
        Element H1m = SP.H1(m);
        Element H1m_p = SP.H1(m_p);
        R_p.R = sk.S_ID.powZn(H1m.sub(H1m_p).div(H1m_p)).mul(R.R.powZn(H1m.div(H1m_p))).getImmutable();
    }
}

