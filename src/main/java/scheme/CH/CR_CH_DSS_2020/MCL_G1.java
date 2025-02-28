package scheme.CH.CR_CH_DSS_2020;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Bringing Order to Chaos：The Case of Collision-Resistant Chameleon-Hashes
 * P25. Construction 3. Concrete instantiation of a Fully Collision-Resistant CH
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public base.GroupParam.MCL.SingleGroup.SingleGroupG1 GP = new base.GroupParam.MCL.SingleGroup.SingleGroupG1();
        public G1 g = new G1();

        public PublicParam() {
            GP.GetGElement(g);
        }

        private void H(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(Fr res, G1 m1, G1 m2, G1 m3, G1 m4, G1 m5, G1 m6, G1 m7) {
            H(res, String.format("(%s(%s|%s)%s)(%s|%s|%s)", m1, m2, m3, m4, m5, m6, m7));
        }
    }

    public static class PublicKey {
        public G1 y = new G1();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public G1 c_1 = new G1(), c_2 = new G1();
    }

    public static class Randomness {
        public Fr e_1 = new Fr(), e_2 = new Fr(), s_1 = new Fr(), s_2 = new Fr();
    }

    private final G1[] G_tmp = new G1[]{new G1(), new G1(), new G1(), new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.mul(pk.y, pp.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp, PublicKey pk, G1 m) {
        pp.GP.GetZrElement(R.e_2);
        pp.GP.GetZrElement(R.s_2);

        pp.GP.GetZrElement(R.s_1);

        Mcl.mul(H.c_1, pp.g, R.s_1);
        Mcl.mul(H.c_2, pk.y, R.s_1);
        Mcl.add(H.c_2, m, H.c_2);

        Mcl.mul(G_tmp[0], pp.g, R.s_2);
        Mcl.mul(G_tmp[2], pk.y, R.e_2);
        Mcl.sub(G_tmp[2], G_tmp[0], G_tmp[2]);

        pp.GP.GetZrElement(Fr_tmp[0]);
        Mcl.mul(G_tmp[0], pp.g, Fr_tmp[0]);
        Mcl.mul(G_tmp[1], pk.y, Fr_tmp[0]);

        pp.H(R.e_1, pk.y, H.c_1, H.c_2, m, G_tmp[0], G_tmp[1], G_tmp[2]);
        Mcl.sub(R.e_1, R.e_1, R.e_2);

        Mcl.mul(R.s_1, R.e_1, R.s_1);
        Mcl.add(R.s_1, R.s_1, Fr_tmp[0]);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, G1 m) {
        Mcl.mul(G_tmp[0], pp.g, R.s_1);
        Mcl.mul(G_tmp[1], H.c_1, R.e_1);
        Mcl.sub(G_tmp[0], G_tmp[0], G_tmp[1]);

        Mcl.mul(G_tmp[1], pk.y, R.s_1);
        Mcl.sub(G_tmp[2], H.c_2, m);
        Mcl.mul(G_tmp[2], G_tmp[2], R.e_1);
        Mcl.sub(G_tmp[1], G_tmp[1], G_tmp[2]);

        Mcl.mul(G_tmp[2], pp.g, R.s_2);
        Mcl.mul(G_tmp[3], pk.y, R.e_2);
        Mcl.sub(G_tmp[2], G_tmp[2], G_tmp[3]);

        pp.H(Fr_tmp[1], pk.y, H.c_1, H.c_2, m, G_tmp[0], G_tmp[1], G_tmp[2]);

        Mcl.add(Fr_tmp[0], R.e_1, R.e_2);
        return Fr_tmp[0].equals(Fr_tmp[1]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp, PublicKey pk, SecretKey sk, G1 m, G1 m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("wrong hash value");
        pp.GP.GetZrElement(R_p.e_1);
        pp.GP.GetZrElement(R_p.s_1);

        pp.GP.GetZrElement(Fr_tmp[0]);

        Mcl.mul(G_tmp[0], pp.g, R_p.s_1);
        Mcl.mul(G_tmp[1], H.c_1, R_p.e_1);
        Mcl.sub(G_tmp[0], G_tmp[0], G_tmp[1]);

        Mcl.mul(G_tmp[1], pk.y, R_p.s_1);
        Mcl.sub(G_tmp[2], H.c_2, m_p);
        Mcl.mul(G_tmp[2], G_tmp[2], R_p.e_1);
        Mcl.sub(G_tmp[1], G_tmp[1], G_tmp[2]);

        Mcl.mul(G_tmp[2], pp.g, Fr_tmp[0]);

        pp.H(R_p.e_2, pk.y, H.c_1, H.c_2, m_p, G_tmp[0], G_tmp[1], G_tmp[2]);

        Mcl.sub(R_p.e_2, R_p.e_2, R_p.e_1);

        Mcl.mul(R_p.s_2, R_p.e_2, sk.x);
        Mcl.add(R_p.s_2, Fr_tmp[0], R_p.s_2);
    }

}
