package scheme.IBCH.ID_B_CollRes_XSL_2021;

import com.herumi.mcl.*;
import utils.Func;

import java.util.BitSet;
import java.util.Random;

/*
 * Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet
 * P4. V. CONSTRUCTION
 */

public class MCL {
    public static class PublicParam {
        G1 g = new G1();
        G1 g_1 = new G1();
        G2 g_2 = new G2();
        G2[] u;
        int n;

        public PublicParam(int n) {
            u = new G2[n + 1];
            for (int i = 0; i <= n; i++) u[i] = new G2();
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
        public G2 g_2_alpha = new G2();
    }

    public static class SecretKey {
        public G2 tk_1 = new G2();
        public G1 tk_2 = new G1();
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
        public GT h = new GT();
    }

    public static class Randomness {
        public G1 r_2 = new G1();
        public G2 r_1 = new G2();
    }

    private static final G2[] G2_tmp = new G2[]{new G2()};
    private static final GT[] GT_tmp = new GT[]{new GT(), new GT(), new GT()};
    private static final Fr[] Fr_tmp = new Fr[]{new Fr()};

    private static void getHashValue(GT h, Randomness R, PublicParam SP, Identity ID, Fr m) {
        Mcl.neg(G2_tmp[0], SP.u[0]);
        Mcl.neg(G2_tmp[0], G2_tmp[0]);
        for(int i = 1;i <= SP.n;++i) {
            if(ID.At(i)) Mcl.add(G2_tmp[0], G2_tmp[0], SP.u[i]);
        }
        Mcl.pairing(h, SP.g_1, SP.g_2);
        Mcl.pow(h, h, m);
        Mcl.pairing(GT_tmp[0], SP.g, R.r_1);
        Mcl.pairing(GT_tmp[1], R.r_2, G2_tmp[0]);
        Mcl.inv(GT_tmp[1], GT_tmp[1]);
        Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);
        Mcl.mul(h, h, GT_tmp[0]);
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);
        Func.GetMCLG1RandomElement(SP.g);
        Func.GetMCLG2RandomElement(SP.g_2);
        Mcl.mul(SP.g_1, SP.g, Fr_tmp[0]);
        for(int i = 0;i <= SP.n;++i) Func.GetMCLG2RandomElement(SP.u[i]);
        Mcl.mul(msk.g_2_alpha, SP.g_2, Fr_tmp[0]);
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, Identity ID) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);

        Mcl.neg(G2_tmp[0], SP.u[0]);
        Mcl.neg(G2_tmp[0], G2_tmp[0]);
        for(int i = 1;i <= SP.n;++i) {
            if(ID.At(i)) Mcl.add(G2_tmp[0], G2_tmp[0], SP.u[i]);
        }
        Mcl.mul(sk.tk_1, G2_tmp[0], Fr_tmp[0]);
        Mcl.add(sk.tk_1, sk.tk_1, msk.g_2_alpha);
        Mcl.mul(sk.tk_2, SP.g, Fr_tmp[0]);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, Identity ID, Fr m) {
        Func.GetMCLG2RandomElement(R.r_1);
        Func.GetMCLG1RandomElement(R.r_2);
        getHashValue(H.h, R, SP, ID, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, Identity ID, Fr m) {
        getHashValue(GT_tmp[2], R, SP, ID, m);
        return H.h.equals(GT_tmp[2]);
    }

    public void Adapt(Randomness R_p, Randomness R, SecretKey sk, Fr m, Fr m_p) {
        Mcl.sub(Fr_tmp[0], m, m_p);
        Mcl.mul(R_p.r_1, sk.tk_1, Fr_tmp[0]);
        Mcl.add(R_p.r_1, R.r_1, R_p.r_1);
        Mcl.mul(R_p.r_2, sk.tk_2, Fr_tmp[0]);
        Mcl.add(R_p.r_2, R.r_2, R_p.r_2);
    }
}
