package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();

        public void H(Fr res, Fr m) {
            Hash.H_MCL_Zr_1(res, m.toString());
        }
    }

    public static class PublicKey {
        public G1 h = new G1(), g = new G1();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class HashValue {
        public G1 h = new G1();
    }

    public static class Randomness {
        public G1 g_r = new G1();
        public base.NIZK.MCL_G1.DH_PAIR_Proof pi;
    }

    private final G1[] G_tmp = new G1[]{new G1(), new G1(), new G1(), new G1(), new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP) {
        PP.GP.GetZrElement(sk.x);
        PP.GP.GetGElement(pk.g);
        Mcl.mul(pk.h, pk.g, sk.x);
    }

    public void Hash(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Fr L, Fr m) {
        PP.H(Fr_tmp[1], L);
        Mcl.mul(G_tmp[3], pk.g, Fr_tmp[1]);
        Mcl.add(G_tmp[3], G_tmp[3], pk.h);

        PP.GP.GetZrElement(Fr_tmp[1]);
        Mcl.mul(G_tmp[4], G_tmp[3], Fr_tmp[1]);
        Mcl.mul(r.g_r, pk.g, Fr_tmp[1]);

        PP.H(Fr_tmp[0], m);
        Mcl.mul(h.h, pk.g, Fr_tmp[0]);
        Mcl.add(h.h, h.h, G_tmp[4]);
        r.pi = new base.NIZK.MCL_G1.DH_PAIR_Proof(Fr_tmp[1], pk.g, r.g_r, G_tmp[3], G_tmp[4], G_tmp, Fr_tmp);
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Fr L, Fr m) {
        PP.H(Fr_tmp[0], L);
        Mcl.mul(G_tmp[3], pk.g, Fr_tmp[0]);
        Mcl.add(G_tmp[3], G_tmp[3], pk.h);

        PP.H(Fr_tmp[0], m);
        Mcl.mul(G_tmp[4], pk.g, Fr_tmp[0]);
        Mcl.sub(G_tmp[4], h.h, G_tmp[4]);
        return r.pi.Check(pk.g, r.g_r, G_tmp[3], G_tmp[4], G_tmp, Fr_tmp) || r.pi.Check(pk.g, G_tmp[3], r.g_r, G_tmp[4], G_tmp, Fr_tmp);
    }

    public void Adapt(Randomness r_p, HashValue h, Randomness r, PublicParam PP, PublicKey pk, SecretKey sk, Fr L, Fr m, Fr m_p) {
        PP.H(Fr_tmp[1], L);
        Mcl.mul(G_tmp[3], pk.g, Fr_tmp[1]);
        Mcl.add(G_tmp[3], G_tmp[3], pk.h);

        Mcl.add(Fr_tmp[1], sk.x, Fr_tmp[1]);

        PP.H(Fr_tmp[0], m);
        PP.H(Fr_tmp[2], m_p);
        Mcl.mul(G_tmp[4], pk.g, Fr_tmp[2]);
        Mcl.sub(G_tmp[4], h.h, G_tmp[4]);

        Mcl.sub(Fr_tmp[0], Fr_tmp[0], Fr_tmp[2]);
        Mcl.div(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);

        Mcl.mul(r_p.g_r, pk.g, Fr_tmp[0]);
        Mcl.add(r_p.g_r, r.g_r, r_p.g_r);
        r_p.pi = new base.NIZK.MCL_G1.DH_PAIR_Proof(Fr_tmp[1], pk.g, G_tmp[3], r_p.g_r, G_tmp[4], G_tmp, Fr_tmp);
    }
}
