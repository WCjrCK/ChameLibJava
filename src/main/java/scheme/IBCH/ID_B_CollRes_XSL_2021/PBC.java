package scheme.IBCH.ID_B_CollRes_XSL_2021;

import it.unisa.dia.gas.jpbc.Element;

import java.util.BitSet;
import java.util.Random;

/*
 * Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet
 * P4. V. CONSTRUCTION
 */

public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Asymmetry GP;
        Element g, g_1, g_2;
        Element[] u;
        int n;

        public PublicParam(curve.PBC curve, boolean swap_G1G2, int n) {
            GP = new base.GroupParam.PBC.Asymmetry(curve, swap_G1G2);
            u = new Element[n + 1];
            this.n = n;
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
        return SP.GP.pairing(SP.g_1, SP.g_2).powZn(m).mul(SP.GP.pairing(SP.g, R.r_1).div(SP.GP.pairing(R.r_2, tmp))).getImmutable();
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        Element alpha = SP.GP.GetZrElement();
        SP.g = SP.GP.GetG1Element();
        SP.g_2 = SP.GP.GetG2Element();
        SP.g_1 = SP.g.powZn(alpha).getImmutable();
        for(int i = 0;i <= SP.n;++i) SP.u[i] = SP.GP.GetG2Element();
        msk.g_2_alpha = SP.g_2.powZn(alpha).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Identity ID) {
        Element t = SP.GP.GetZrElement();
        Element tmp = SP.u[0].getImmutable();
        for(int i = 1;i <= SP.n;++i) {
            if(ID.At(i)) tmp = tmp.mul(SP.u[i]).getImmutable();
        }
        sk.tk_1 = msk.g_2_alpha.mul(tmp.powZn(t)).getImmutable();
        sk.tk_2 = SP.g.powZn(t).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Identity ID, Element m) {
        R.r_1 = SP.GP.GetG2Element();
        R.r_2 = SP.GP.GetG1Element();
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
