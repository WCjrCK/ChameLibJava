package scheme.IBCH.IB_CH_ZSS_S2_2003;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.2 Scheme 2
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        Field Zr, G, GT;
        Element P, P_pub;

        public Element pairing(Element g1, Element g2) {
            return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H1(Element m) {
            return Hash.H_PBC_1_1(Zr, m);
        }

        public Element GetGElement() {
            return G.newRandomElement().getImmutable();
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
        return SP.pairing(SP.P, SP.P).mul(SP.pairing(SP.P.powZn(SP.H1(ID)).mul(SP.P_pub), R.R)).powZn(SP.H1(m)).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk, curve.PBC curve) {
        SP.pairing = Func.PairingGen(curve);
        SP.G = SP.pairing.getG1();
        SP.GT = SP.pairing.getGT();
        SP.Zr = SP.pairing.getZr();
        SP.P = SP.GetGElement();
        msk.s = SP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.s).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.P.powZn(msk.s.add(SP.H1(ID)).invert()).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element m) {
        R.R = SP.GetGElement();
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

