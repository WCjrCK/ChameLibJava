package scheme.CH.FCR_CH_PreQA_DKS_2020;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Fully Collision-Resistant Chameleon-Hashes from Simpler and Post-Quantum Assumptions
 * P15. Construction 2: Concrete instantiation from DLOG
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();
        public G1 g_1 = new G1(), g_2 = new G1();

        public PublicParam() {
            GP.GetGElement(g_1);
            H_p(g_2, g_1);
        }

        private void H(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(Fr res, G1 m1, G1 m2, Fr m3, G1 m4, G1 m5) {
            H(res, String.format("(%s|%s|%s)(%s|%s)", m1, m2, m3, m4, m5));
        }

        public void H_p(G1 res, G1 m) {
            Hash.H_MCL_G1_1(res, m.toString());
        }
    }

    public static class PublicKey {
        public G1 y = new G1();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public G1 O = new G1();
    }

    public static class Randomness {
        public Fr e_1 = new Fr(), e_2 = new Fr(), s_1_1 = new Fr(), s_1_2 = new Fr(), s_2 = new Fr();
    }

    private final G1[] G_tmp = new G1[]{new G1(), new G1(), new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.mul(pk.y, pp.g_1, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        pp.GP.GetZrElement(R.e_2);
        pp.GP.GetZrElement(R.s_2);

        pp.GP.GetZrElement(R.s_1_2);

        Mcl.mul(H.O, pp.g_1, m);
        Mcl.mul(G_tmp[0], pp.g_2, R.s_1_2);
        Mcl.add(H.O, H.O, G_tmp[0]);

        pp.GP.GetZrElement(Fr_tmp[0]);

        pp.GP.GetZrElement(R.s_1_1);

        Mcl.mul(G_tmp[0], pp.g_1, Fr_tmp[0]);
        Mcl.mul(G_tmp[1], pp.g_2, R.s_1_1);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);

        Mcl.mul(G_tmp[1], pp.g_1, R.s_2);
        Mcl.mul(G_tmp[2], pk.y, R.e_2);
        Mcl.sub(G_tmp[1], G_tmp[1], G_tmp[2]);

        pp.H(R.e_1, pk.y, H.O, m, G_tmp[0], G_tmp[1]);
        Mcl.sub(R.e_1, R.e_1, R.e_2);

        Mcl.mul(R.s_1_2, R.e_1, R.s_1_2);
        Mcl.add(R.s_1_2, R.s_1_1, R.s_1_2);

        Mcl.mul(R.s_1_1, R.e_1, m);
        Mcl.add(R.s_1_1, Fr_tmp[0], R.s_1_1);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        Mcl.add(Fr_tmp[0], R.e_1, R.e_2);

        Mcl.mul(G_tmp[0], pp.g_1, R.s_1_1);
        Mcl.mul(G_tmp[1], pp.g_2, R.s_1_2);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        Mcl.mul(G_tmp[1], H.O, R.e_1);
        Mcl.sub(G_tmp[0], G_tmp[0], G_tmp[1]);

        Mcl.mul(G_tmp[1], pp.g_1, R.s_2);
        Mcl.mul(G_tmp[2], pk.y, R.e_2);
        Mcl.sub(G_tmp[1], G_tmp[1], G_tmp[2]);

        pp.H(Fr_tmp[1], pk.y, H.O, m, G_tmp[0], G_tmp[1]);
        return Fr_tmp[0].equals(Fr_tmp[1]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R,PublicParam pp, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        pp.GP.GetZrElement(Fr_tmp[0]);
        pp.GP.GetZrElement(R_p.e_1);
        pp.GP.GetZrElement(R_p.s_1_1);
        pp.GP.GetZrElement(R_p.s_1_2);

        Mcl.mul(G_tmp[0], pp.g_1, R_p.s_1_1);
        Mcl.mul(G_tmp[1], pp.g_2, R_p.s_1_2);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        Mcl.mul(G_tmp[1], H.O, R_p.e_1);
        Mcl.sub(G_tmp[0], G_tmp[0], G_tmp[1]);

        Mcl.mul(G_tmp[1], pp.g_1, Fr_tmp[0]);
        pp.H(R_p.e_2, pk.y, H.O, m_p, G_tmp[0], G_tmp[1]);
        Mcl.sub(R_p.e_2, R_p.e_2, R_p.e_1);

        Mcl.mul(R_p.s_2, R_p.e_2, sk.x);
        Mcl.add(R_p.s_2, Fr_tmp[0], R_p.s_2);
    }
}
