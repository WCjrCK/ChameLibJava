package scheme.CH.CH_FS_ECC_CCT_2024;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting
 * P6. 3.2 ECC-based Construction
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_GT {
    public static class PublicParam {
        public SingleGroup.SingleGroupGT GP = new SingleGroup.SingleGroupGT();
        public GT g = new GT();

        public PublicParam() {
            GP.GetGElement(g);
        }

        private void H_p(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(GT res, Fr m) {
            Hash.H_MCL_GT_1(res, m.toString());
        }

        public void H_p(Fr res, GT m1, GT m2, GT m3, Fr m4) {
            H_p(res, String.format("%s|%s|%s|%s", m1, m2, m3, m4));
        }
    }

    public static class PublicKey {
        public GT g_x = new GT();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public GT h = new GT();
    }

    public static class Randomness {
        public Fr z_1 = new Fr(), z_2 = new Fr(), c_1 = new Fr();
    }

    private final GT[] G_tmp = new GT[]{new GT(), new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.pow(pk.g_x, pp.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        pp.GP.GetZrElement(Fr_tmp[0]);
        Mcl.pow(H.h, pp.g, Fr_tmp[0]);

        pp.GP.GetZrElement(Fr_tmp[1]);

        Mcl.pow(G_tmp[0], pp.g, Fr_tmp[1]);
        pp.H_p(R.c_1, G_tmp[0], pk.g_x, H.h, m);

        pp.GP.GetZrElement(R.z_1);
        Mcl.pow(G_tmp[0], pp.g, R.z_1);
        Mcl.pow(G_tmp[1], pk.g_x, R.c_1);
        Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
        pp.H_p(R.z_2, G_tmp[0], pk.g_x, H.h, m);

        Mcl.mul(R.z_2, R.z_2, Fr_tmp[0]);
        Mcl.sub(R.z_2, Fr_tmp[1], R.z_2);

        pp.H(G_tmp[0], m);
        Mcl.mul(H.h, H.h, G_tmp[0]);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        pp.H(G_tmp[0], m);
        Mcl.inv(G_tmp[0], G_tmp[0]);
        Mcl.mul(G_tmp[0], H.h, G_tmp[0]);

        Mcl.pow(G_tmp[1], pp.g, R.z_1);
        Mcl.pow(G_tmp[2], pk.g_x, R.c_1);
        Mcl.mul(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(Fr_tmp[0], G_tmp[1], pk.g_x, G_tmp[0], m);

        Mcl.pow(G_tmp[1], pp.g, R.z_2);
        Mcl.pow(G_tmp[2], G_tmp[0], Fr_tmp[0]);
        Mcl.mul(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(Fr_tmp[0], G_tmp[1], pk.g_x, G_tmp[0], m);
        return R.c_1.equals(Fr_tmp[0]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        pp.H(G_tmp[0], m_p);
        Mcl.inv(G_tmp[0], G_tmp[0]);
        Mcl.mul(G_tmp[0], H.h, G_tmp[0]);
        pp.GP.GetZrElement(Fr_tmp[0]);
        pp.GP.GetZrElement(R_p.z_2);
        Mcl.pow(G_tmp[1], pp.g, Fr_tmp[0]);
        pp.H_p(Fr_tmp[1], G_tmp[1], pk.g_x, G_tmp[0], m_p);

        Mcl.pow(G_tmp[1], pp.g, R_p.z_2);
        Mcl.pow(G_tmp[2], G_tmp[0], Fr_tmp[1]);
        Mcl.mul(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(R_p.c_1, G_tmp[1], pk.g_x, G_tmp[0], m_p);

        Mcl.mul(R_p.z_1, R_p.c_1, sk.x);
        Mcl.sub(R_p.z_1, Fr_tmp[0], R_p.z_1);
    }
}
