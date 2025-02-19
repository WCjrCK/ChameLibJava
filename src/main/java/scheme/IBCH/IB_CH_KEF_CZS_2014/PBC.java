package scheme.IBCH.IB_CH_KEF_CZS_2014;

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
        Field Zr, G1, G2, GT;
        boolean swap_G1G2;
        Element P, P_pub;

        public Element pairing(Element g1, Element g2) {
            if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
            else return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H_G1(Element m) {
            return Hash.H_PBC_1_1(G1, m);
        }

        public Element H_G2(Element m) {
            return Hash.H_PBC_1_1(G2, m);
        }

        public Element GetG1Element() {
            return G1.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
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
        return R.r_1.add(SP.H_G1(L).powZn(m)).getImmutable();
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
        SP.P = SP.GetG1Element();
        msk.x = SP.GetZrElement();
        SP.P_pub = SP.P.powZn(msk.x).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Element ID) {
        sk.S_ID = SP.H_G2(ID).powZn(msk.x).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Element ID, Element L, Element m) {
        Element a = SP.GetZrElement();
        R.r_1 = SP.P.powZn(a).getImmutable();
        R.r_2 = SP.pairing(SP.P_pub.powZn(a), SP.H_G2(ID));
        H.h = R.r_1.mul(SP.H_G1(L).powZn(m)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Element L, Element m) {
        return H.h.isEqual(getHashValue(R, SP, L, m));
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, Element L, Element m, Element m_p) {
        Element delta_m = m.sub(m_p);
        R_p.r_1 = R.r_1.mul(SP.H_G1(L).powZn(delta_m)).getImmutable();
        R_p.r_2 = R.r_2.mul(SP.pairing(SP.H_G1(L), sk.S_ID).powZn(delta_m)).getImmutable();
    }
}
