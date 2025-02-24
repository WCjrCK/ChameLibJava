package scheme.IBCH.ID_B_CollRes_XSL_2021;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

import java.util.BitSet;
import java.util.Random;

/*
 * Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet
 * P4. V. CONSTRUCTION
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        Field Zr, G1, G2, GT;
        boolean swap_G1G2;
        Element g, g_1, g_2;
        Element[] u;
        int n;

        public Element pairing(Element g1, Element g2) {
            if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
            else return pairing.pairing(g1, g2).getImmutable();
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

        public Identity GenIdentity() {
            Random rand = new Random();
            Identity res = new Identity(n);
            for(int i = 1; i <= n; i++) res.Set(i, rand.nextBoolean());
            return res;
        }
    }

    public static class MasterSecretKey {
        public Element g_2_alpha;
    }

    public static class SecretKey {
        public Element tk_1, tk_2;
    }

    public static class Identity {
        BitSet I;

        public Identity(int n) {
            I = new BitSet(n);
        }

        public boolean At(int i) {
            return I.get(i - 1);
        }

        public void Set(int i, boolean x) {
            I.set(i - 1, x);
        }
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element r_1, r_2;
    }

    private static Element getHashValue(Randomness R, PublicParam SP, Identity ID, Element m) {
        Element tmp = SP.u[0].getImmutable();
        for(int i = 1;i <= SP.n;++i) {
            if(ID.At(i)) tmp = tmp.mul(SP.u[i]).getImmutable();
        }
        return SP.pairing(SP.g_1, SP.g_2).powZn(m).mul(SP.pairing(SP.g, R.r_1).div(SP.pairing(R.r_2, tmp))).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk, curve.PBC curve, int n, boolean swap_G1G2) {
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
        SP.u = new Element[n + 1];
        SP.n = n;
        Element alpha = SP.GetZrElement();
        SP.g = SP.GetG1Element();
        SP.g_2 = SP.GetG2Element();
        SP.g_1 = SP.g.powZn(alpha).getImmutable();
        for(int i = 0;i <= n;++i) SP.u[i] = SP.GetG2Element();
        msk.g_2_alpha = SP.g_2.powZn(alpha).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Identity ID) {
        Element t = SP.GetZrElement();
        Element tmp = SP.u[0].getImmutable();
        for(int i = 1;i <= SP.n;++i) {
            if(ID.At(i)) tmp = tmp.mul(SP.u[i]).getImmutable();
        }
        sk.tk_1 = msk.g_2_alpha.mul(tmp.powZn(t)).getImmutable();
        sk.tk_2 = SP.g.powZn(t).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Identity ID, Element m) {
        R.r_1 = SP.GetG2Element();
        R.r_2 = SP.GetG1Element();
        H.h = getHashValue(R, SP, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Identity ID, Element m) {
        return H.h.isEqual(getHashValue(R, SP, ID, m));
    }

    public void Adapt(Randomness R_p, Randomness R, SecretKey sk, Element m, Element m_p) {
        Element delta_m = m.sub(m_p).getImmutable();
        R_p.r_1 = R.r_1.mul(sk.tk_1.powZn(delta_m)).getImmutable();
        R_p.r_2 = R.r_2.mul(sk.tk_2.powZn(delta_m)).getImmutable();
    }
}
