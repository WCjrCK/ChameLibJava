package scheme.IBCH.IB_CH_KEF_CZS_2014;

import com.herumi.mcl.*;
import utils.Func;
import utils.Hash;

/*
 * Identity-based chameleon hashing and signatures without key exposure
 * P6. 4.1. The proposed identity-based chameleon hash scheme
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL {
    public static class PublicParam {
        public G1 P = new G1(), P_pub = new G1();

        public void H_G1(G1 res, String m) {
            Hash.H_MCL_G1_1(res, m);
        }

        public void H_G2(G2 res, String m) {
            Hash.H_MCL_G2_1(res, m);
        }
    }

    public static class MasterSecretKey {
        public Fr x = new Fr();
    }

    public static class SecretKey {
        public G2 S_ID = new G2();
    }

    public static class HashValue {
        public G1 h = new G1();
    }

    public static class Randomness {
        public G1 r_1 = new G1();
        public GT r_2 = new GT();
    }

    private final G1[] G1_tmp = new G1[]{new G1()};
    private final G2[] G2_tmp = new G2[]{new G2()};
    private final GT[] GT_tmp = new GT[]{new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr()};


    private static void getHashValue(G1 h, Randomness R, PublicParam SP, String L, Fr m) {
        SP.H_G1(h, L);
        Mcl.mul(h, h, m);
        Mcl.add(h, R.r_1, h);
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk) {
        Func.GetMCLG1RandomElement(SP.P);
        Func.GetMCLZrRandomElement(msk.x);
        Mcl.mul(SP.P_pub, SP.P, msk.x);
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterSecretKey msk, String ID) {
        SP.H_G2(sk.S_ID, ID);
        Mcl.mul(sk.S_ID, sk.S_ID, msk.x);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, String ID, String L, Fr m) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);
        Mcl.mul(R.r_1, SP.P_pub, Fr_tmp[0]);
        SP.H_G2(G2_tmp[0], ID);
        Mcl.pairing(R.r_2, R.r_1, G2_tmp[0]);
        Mcl.mul(R.r_1, SP.P, Fr_tmp[0]);
        getHashValue(H.h, R, SP, L, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, SecretKey sk, String L, Fr m) {
        Mcl.pairing(GT_tmp[0], R.r_1, sk.S_ID);
        getHashValue(G1_tmp[0], R, SP, L, m);
        return R.r_2.equals(GT_tmp[0]) && H.h.equals(G1_tmp[0]);
    }

    public void Adapt(Randomness R_p, Randomness R, PublicParam SP, SecretKey sk, String L, Fr m, Fr m_p) {
        Mcl.sub(Fr_tmp[0], m, m_p);
        SP.H_G1(R_p.r_1, L);
        Mcl.pairing(R_p.r_2, R_p.r_1, sk.S_ID);
        Mcl.pow(R_p.r_2, R_p.r_2, Fr_tmp[0]);
        Mcl.mul(R_p.r_2, R.r_2, R_p.r_2);
        Mcl.mul(R_p.r_1, R_p.r_1, Fr_tmp[0]);
        Mcl.add(R_p.r_1, R.r_1, R_p.r_1);
        Mcl.pairing(GT_tmp[0], R_p.r_1, sk.S_ID);
        if(!R_p.r_2.equals(GT_tmp[0])) throw new RuntimeException("adapt failed");
    }
}
