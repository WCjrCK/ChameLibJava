package scheme.IBCH.IB_CH_ZSS_S1_2003;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.1 Scheme 1
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        Field Zr, G1, G2, GT;
        boolean swap_G1G2;
        Element P, P_pub;

        public Element pairing(Element g1, Element g2) {
            if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
            else return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H0(Element m) {
            return Hash.H_PBC_1_1(G1, m);
        }

        public Element H1(Element m) {
            return Hash.H_PBC_1_1(Zr, m);
        }

        public Element GetG2Element() {
            return G2.newRandomElement().getImmutable();
        }

        public Element GetG1Element() {
            return G1.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
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
        return SP.pairing(R.R, SP.P).mul(SP.pairing(SP.H0(ID).powZn(SP.H1(m)), SP.P_pub)).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk, curve.PBC curve, boolean swap_G1G2) {
        SP.swap_G1G2 = swap_G1G2;
        SP.pairing = Func.PairingGen(curve);
        if(swap_G1G2) {
            SP.G1 = SP.pairing.getG2();
            SP.G2 = SP.pairing.getG1();
        } else {
            SP.G1 = SP.pairing.getG1();
            SP.G2 = SP.pairing.getG2();
        }
        SP.GT = SP.pairing.getGT();
        SP.Zr = SP.pairing.getZr();
        SP.P = SP.GetG2Element();
        msk.s = SP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.s).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.H0(ID).powZn(msk.s).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        R.R = SP.GetG1Element();
        H.h = getHashValue(R, SP, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        return H.h.isEqual(getHashValue(R, SP, ID, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element m, Element m_p) {
        R_p.R = R.R.mul(sk.S_ID.powZn(SP.H1(m).sub(SP.H1(m_p)))).getImmutable();
    }
}
