package AE.PKE_CPA_AMV_2017;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.util.HashMap;

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();
        public G1 g = new G1();

        // due to wrong behave in many curve & group at elementfrombyte, have to make map to implement Omega
        public HashMap<String, G1> Omega = new HashMap<>();
        public HashMap<String, Fr> Omega_inv = new HashMap<>();

        public void H(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(Fr res, G1 m1, G1 m2, G1 m3) {
            H(res, String.format("%s|%s|%s", m1, m2, m3));
        }

        public G1 Omega(Fr m) {
            if(Omega.containsKey(m.toString())) return Omega.get(m.toString());
            G1 res = new G1();
            GP.GetGElement(res);
            Omega.put(m.toString(), res);
            Omega_inv.put(res.toString(), m);
            return res;
        }

        public Fr Omega_inv(G1 m) {
            return Omega_inv.get(m.toString());
        }
    }

    public static class PublicKey {
        public G1 y = new G1();
    }

    public static class SecretKey {
        public Fr x = new Fr();
    }

    public static class CipherText {
        public G1 c_1 = new G1(), c_2 = new G1();
    }

    public static class PlainText {
        public Fr m = new Fr();

        public boolean isEqual(PlainText pt) {
            return m.equals(pt.m);
        }
    }

    private final G1[] G_tmp = new G1[]{new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr()};

    public void SetUp(PublicParam pp) {
        pp.GP.GetGElement(pp.g);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.mul(pk.y, pp.g, sk.x);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT) {
        pp.GP.GetZrElement(Fr_tmp[0]);
        Encrypt(CT, pp, pk, PT, Fr_tmp[0]);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT, Fr rho) {
        Mcl.mul(CT.c_1, pp.g, rho);
        Mcl.mul(CT.c_2, pk.y, rho);
        Mcl.add(CT.c_2, CT.c_2, pp.Omega(PT.m));
    }

    public void Decrypt(PlainText PT, PublicParam pp, SecretKey sk, CipherText CT) {
        Mcl.mul(G_tmp[0], CT.c_1, sk.x);
        Mcl.sub(G_tmp[0], CT.c_2, G_tmp[0]);
        PT.m = pp.Omega_inv(G_tmp[0]);
    }
}
