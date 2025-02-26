package scheme.CH.CH_KEF_CZK_2004;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * Chameleon Hashing without Key Exposure
 * P7. 3.3.1 The scheme
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();
        G1 g;

        public PublicParam() {
            g = GP.GetGElement();
        }

        public G1 H(String m) {
            return Hash.H_MCL_G1_1(m);
        }
    }

    public static class PublicKey {
        public G1 y = new G1();
    }

    public static class SecretKey {
        public Fr x;
    }

    public static class HashValue {
        public G1 h = new G1();
    }

    public static class Randomness {
        public G1 g_a = new G1(), y_a = new G1();
    }

    private static void getHashValue(G1 res, Randomness R, PublicParam SP, G1 I, Fr m) {
        Mcl.add(res, SP.g, I);
        Mcl.mul(res, res, m);
        Mcl.add(res, res, R.y_a);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam SP) {
        sk.x = SP.GP.GetZrElement();
        Mcl.mul(pk.y, SP.g, sk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, PublicKey pk, G1 I, Fr m) {
        Fr a = SP.GP.GetZrElement();
        Mcl.mul(R.g_a, SP.g, a);
        Mcl.mul(R.y_a, pk.y, a);
        getHashValue(H.h, R, SP, I, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, G1 I, Fr m) {
        G1 tmp = new G1();
        getHashValue(tmp, R, SP, I, m);
        return H.h.equals(tmp);
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, G1 I, Fr m, Fr m_p) {
        G1 gI = new G1();
        Mcl.add(gI, SP.g, I);
        Fr delta_m = new Fr();
        Mcl.sub(delta_m, m, m_p);
        Mcl.mul(R_p.y_a, gI, delta_m);
        Mcl.add(R_p.y_a, R_p.y_a, R.y_a);

        Mcl.div(delta_m, delta_m, sk.x);
        Mcl.mul(R_p.g_a, gI, delta_m);
        Mcl.add(R_p.g_a, R_p.g_a, R.g_a);
    }
}
