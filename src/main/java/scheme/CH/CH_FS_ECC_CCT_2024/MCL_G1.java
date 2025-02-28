package scheme.CH.CH_FS_ECC_CCT_2024;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting
 * P6. 3.2 ECC-based Construction
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();
        public G1 g = new G1();

        public PublicParam() {
            GP.GetGElement(g);
        }

        private void H_p(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(G1 res, Fr m) {
            Hash.H_MCL_G1_1(res, m.toString());
        }

        public void H_p(Fr res, G1 m1, G1 m2, G1 m3, Fr m4) {
            H_p(res, String.format("%s|%s|%s|%s", m1, m2, m3, m4));
        }
    }

    public static class PublicKey {
        public G1 g_x = new G1();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public G1 h = new G1();
    }

    public static class Randomness {
        public Fr z_1 = new Fr(), z_2 = new Fr(), c_1 = new Fr();
    }

    private final G1[] G_tmp = new G1[]{new G1(), new G1(), new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.mul(pk.g_x, pp.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        pp.GP.GetZrElement(Fr_tmp[0]);
        Mcl.mul(H.h, pp.g, Fr_tmp[0]);

        pp.GP.GetZrElement(Fr_tmp[1]);

        Mcl.mul(G_tmp[0], pp.g, Fr_tmp[1]);
        pp.H_p(R.c_1, G_tmp[0], pk.g_x, H.h, m);

        pp.GP.GetZrElement(R.z_1);
        Mcl.mul(G_tmp[0], pp.g, R.z_1);
        Mcl.mul(G_tmp[1], pk.g_x, R.c_1);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        pp.H_p(R.z_2, G_tmp[0], pk.g_x, H.h, m);

        Mcl.mul(R.z_2, R.z_2, Fr_tmp[0]);
        Mcl.sub(R.z_2, Fr_tmp[1], R.z_2);

        pp.H(G_tmp[0], m);
        Mcl.add(H.h, H.h, G_tmp[0]);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        pp.H(G_tmp[0], m);
        Mcl.sub(G_tmp[0], H.h, G_tmp[0]);

        Mcl.mul(G_tmp[1], pp.g, R.z_1);
        Mcl.mul(G_tmp[2], pk.g_x, R.c_1);
        Mcl.add(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(Fr_tmp[0], G_tmp[1], pk.g_x, G_tmp[0], m);

        Mcl.mul(G_tmp[1], pp.g, R.z_2);
        Mcl.mul(G_tmp[2], G_tmp[0], Fr_tmp[0]);
        Mcl.add(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(Fr_tmp[0], G_tmp[1], pk.g_x, G_tmp[0], m);
        return R.c_1.equals(Fr_tmp[0]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        pp.H(G_tmp[0], m_p);
        Mcl.sub(G_tmp[0], H.h, G_tmp[0]);
        pp.GP.GetZrElement(Fr_tmp[0]);
        pp.GP.GetZrElement(R_p.z_2);
        Mcl.mul(G_tmp[1], pp.g, Fr_tmp[0]);
        pp.H_p(Fr_tmp[1], G_tmp[1], pk.g_x, G_tmp[0], m_p);

        Mcl.mul(G_tmp[1], pp.g, R_p.z_2);
        Mcl.mul(G_tmp[2], G_tmp[0], Fr_tmp[1]);
        Mcl.add(G_tmp[1], G_tmp[1], G_tmp[2]);
        pp.H_p(R_p.c_1, G_tmp[1], pk.g_x, G_tmp[0], m_p);

        Mcl.mul(R_p.z_1, R_p.c_1, sk.x);
        Mcl.sub(R_p.z_1, Fr_tmp[0], R_p.z_1);
    }
}
