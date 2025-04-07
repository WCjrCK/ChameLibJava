package scheme.CH.CH_KEF_CZK_2004;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Chameleon Hashing without Key Exposure
 * P7. 3.3.1 The scheme
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_GT {
    public static class PublicParam {
        public SingleGroup.SingleGroupGT GP = new SingleGroup.SingleGroupGT();
        GT g = new GT();

        public PublicParam() {
            GP.GetGElement(g);
        }

        public void H(GT res, String m) {
            Hash.H_MCL_GT_1(res, m);
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

    private static void getHashValue(GT res, Randomness R, PublicParam SP, GT I, Fr m) {
        Mcl.mul(res, SP.g, I);
        Mcl.pow(res, res, m);
        Mcl.mul(res, res, R.y_a);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        SP.GP.GetZrElement(sk.x);
        Mcl.pow(pk.y, SP.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, GT I, Fr m) {
        SP.GP.GetZrElement(Fr_tmp[0]);
        Mcl.pow(R.g_a, SP.g, Fr_tmp[0]);
        Mcl.pow(R.y_a, pk.y, Fr_tmp[0]);
        getHashValue(H.h, R, SP, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, GT I, Fr m) {
        getHashValue(G_tmp[0], R, SP, I, m);
        return H.h.equals(G_tmp[0]);
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, GT I, Fr m, Fr m_p) {
        Mcl.mul(R_p.g_a, SP.g, I);
        Mcl.sub(Fr_tmp[0], m, m_p);
        Mcl.pow(R_p.y_a, R_p.g_a, Fr_tmp[0]);
        Mcl.mul(R_p.y_a, R_p.y_a, R.y_a);

        Mcl.div(Fr_tmp[0], Fr_tmp[0], sk.x);
        Mcl.pow(R_p.g_a, R_p.g_a, Fr_tmp[0]);
        Mcl.mul(R_p.g_a, R_p.g_a, R.g_a);
    }
}
