package AE.PKE_CPA_AMV_2017;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.util.HashMap;

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_GT {
    public static class PublicParam {
        public SingleGroup.SingleGroupGT GP = new SingleGroup.SingleGroupGT();
        public GT g = new GT();

        // due to wrong behave in many curve & group at elementfrombyte, have to make map to implement Omega
        public HashMap<String, GT> Omega = new HashMap<>();
        public HashMap<String, Fr> Omega_inv = new HashMap<>();

        public void H(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(Fr res, GT m1, GT m2, GT m3) {
            H(res, String.format("%s|%s|%s", m1, m2, m3));
        }

        public GT Omega(Fr m) {
            if(Omega.containsKey(m.toString())) return Omega.get(m.toString());
            GT res = new GT();
            GP.GetGElement(res);
            Omega.put(m.toString(), res);
            Omega_inv.put(res.toString(), m);
            return res;
        }

        public Fr Omega_inv(GT m) {
            return Omega_inv.get(m.toString());
        }
    }

    public static class PublicKey {
        public GT y = new GT();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class CipherText {
        public GT c_1 = new GT(), c_2 = new GT();
    }

    public static class PlainText {
        public Fr m = new Fr();

        public boolean isEqual(PlainText pt) {
            return m.equals(pt.m);
        }
    }

    private final GT[] G_tmp = new GT[]{new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr()};

    public void SetUp(PublicParam pp) {
        pp.GP.GetGElement(pp.g);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.pow(pk.y, pp.g, sk.x);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT) {
        pp.GP.GetZrElement(Fr_tmp[0]);
        Encrypt(CT, pp, pk, PT, Fr_tmp[0]);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT, Fr rho) {
        Mcl.pow(CT.c_1, pp.g, rho);
        Mcl.pow(CT.c_2, pk.y, rho);
        Mcl.mul(CT.c_2, CT.c_2, pp.Omega(PT.m));
    }

    public void Decrypt(PlainText PT, PublicParam pp, SecretKey sk, CipherText CT) {
        Mcl.pow(G_tmp[0], CT.c_1, sk.x);
        Mcl.inv(G_tmp[0], G_tmp[0]);
        Mcl.mul(G_tmp[0], CT.c_2, G_tmp[0]);
        PT.m = pp.Omega_inv(G_tmp[0]);
    }
}
