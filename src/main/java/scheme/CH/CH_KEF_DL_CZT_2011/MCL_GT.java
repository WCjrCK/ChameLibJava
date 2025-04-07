package scheme.CH.CH_KEF_DL_CZT_2011;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Discrete logarithm based chameleon hashing and signatures without key exposure
 * P4. 4.1. The proposed chameleon hash scheme
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_GT {
    public static class PublicParam {
        public SingleGroup.SingleGroupGT GP = new SingleGroup.SingleGroupGT();
        GT g = new GT();

        public PublicParam() {
            GP.GetGElement(g);
        }

        public void H(GT res, GT m1, Fr m2) {
            Hash.H_MCL_GT_1(res, String.format("%s|%s", m1, m2));
        }
    }

    public static class PublicKey {
        public GT y = new GT();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public GT h = new GT();
    }

    public static class Randomness {
        public GT g_a = new GT(), y_a = new GT();
    }

    private final GT[] G_tmp = new GT[]{new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr()};

    private static void getHashValue(GT res, Randomness R, PublicParam SP, PublicKey pk, Fr I, Fr m) {
        SP.H(res, pk.y, I);
        Mcl.pow(res, res, m);
        Mcl.mul(res, R.g_a, res);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        SP.GP.GetZrElement(sk.x);
        Mcl.pow(pk.y, SP.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Fr I, Fr m) {
        SP.GP.GetZrElement(Fr_tmp[0]);
        Mcl.pow(R.g_a, SP.g, Fr_tmp[0]);
        Mcl.pow(R.y_a, pk.y, Fr_tmp[0]);
        getHashValue(H.h, R, SP, pk, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, PublicKey pk, Fr I, Fr m) {
        getHashValue(G_tmp[0], R, SP, pk, I, m);
        return H.h.equals(G_tmp[0]);
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, PublicKey pk, SecretKey sk, Fr I, Fr m, Fr m_p) {
        SP.H(R_p.y_a, pk.y, I);
        Mcl.sub(Fr_tmp[0], m, m_p);
        Mcl.pow(R_p.g_a, R_p.y_a, Fr_tmp[0]);
        Mcl.mul(R_p.g_a, R_p.g_a, R.g_a);

        Mcl.mul(Fr_tmp[0], Fr_tmp[0], sk.x);
        Mcl.pow(R_p.y_a, R_p.y_a, Fr_tmp[0]);
        Mcl.mul(R_p.y_a, R_p.y_a, R.y_a);
    }
}