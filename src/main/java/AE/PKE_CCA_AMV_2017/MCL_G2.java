package AE.PKE_CCA_AMV_2017;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.util.HashMap;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G2 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG2 GP = new SingleGroup.SingleGroupG2();
        public G2 g_1 = new G2(), g_2 = new G2();

        // due to wrong behave in many curve & group at elementfrombyte, have to make map to implement Omega
        public HashMap<String, G2> Omega = new HashMap<>();
        public HashMap<String, Fr> Omega_inv = new HashMap<>();

        public void H(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }

        public void H(Fr res, G2 m1, G2 m2, G2 m3) {
            H(res, String.format("%s|%s|%s", m1, m2, m3));
        }

        public G2 Omega(Fr m) {
            if(Omega.containsKey(m.toString())) return Omega.get(m.toString());
            G2 res = new G2();
            GP.GetGElement(res);
            Omega.put(m.toString(), res);
            Omega_inv.put(res.toString(), m);
            return res;
        }

        public Fr Omega_inv(G2 m) {
            return Omega_inv.get(m.toString());
        }
    }

    public static class PublicKey {
        public G2 y_1 = new G2(), y_2 = new G2(), y_3 = new G2();
    }

    public static class SecretKey {
        public Fr x_1_1 = new Fr(), x_2_1 = new Fr(), x_1_2 = new Fr(), x_2_2 = new Fr(), x_1_3 = new Fr(), x_2_3 = new Fr();
    }

    public static class CipherText {
        public G2 c_1 = new G2(), c_2 = new G2(), c_3 = new G2(), c_4 = new G2();
    }

    public static class PlainText {
        public Fr m = new Fr();

        public boolean isEqual(PlainText pt) {
            return m.equals(pt.m);
        }
    }

    private final G2[] G_tmp = new G2[]{new G2(), new G2(), new G2()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    public void SetUp(PublicParam pp) {
        pp.GP.GetGElement(pp.g_1);
        pp.GP.GetGElement(pp.g_2);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x_1_1);
        pp.GP.GetZrElement(sk.x_2_1);
        pp.GP.GetZrElement(sk.x_1_2);
        pp.GP.GetZrElement(sk.x_2_2);
        pp.GP.GetZrElement(sk.x_1_3);
        pp.GP.GetZrElement(sk.x_2_3);
        Mcl.mul(pk.y_1, pp.g_1, sk.x_1_1);
        Mcl.mul(G_tmp[0], pp.g_2, sk.x_2_1);
        Mcl.add(pk.y_1, pk.y_1, G_tmp[0]);

        Mcl.mul(pk.y_2, pp.g_1, sk.x_1_2);
        Mcl.mul(G_tmp[0], pp.g_2, sk.x_2_2);
        Mcl.add(pk.y_2, pk.y_2, G_tmp[0]);

        Mcl.mul(pk.y_3, pp.g_1, sk.x_1_3);
        Mcl.mul(G_tmp[0], pp.g_2, sk.x_2_3);
        Mcl.add(pk.y_3, pk.y_3, G_tmp[0]);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT) {
        pp.GP.GetZrElement(Fr_tmp[1]);
        Encrypt(CT, pp, pk, PT, Fr_tmp[1]);
    }

    public void Encrypt(CipherText CT, PublicParam pp, PublicKey pk, PlainText PT, Fr rho) {
        Mcl.mul(CT.c_1, pp.g_1, rho);
        Mcl.mul(CT.c_2, pp.g_2, rho);
        Mcl.mul(CT.c_3, pk.y_3, rho);
        Mcl.add(CT.c_3, CT.c_3, pp.Omega(PT.m));
        Mcl.mul(CT.c_4, pk.y_1, rho);
        pp.H(Fr_tmp[0], CT.c_1, CT.c_2, CT.c_3);
        Mcl.mul(Fr_tmp[0], rho, Fr_tmp[0]);
        Mcl.mul(G_tmp[0], pk.y_2, Fr_tmp[0]);
        Mcl.add(CT.c_4, CT.c_4, G_tmp[0]);
    }

    public void Decrypt(PlainText PT, PublicParam pp, SecretKey sk, CipherText CT) {
        pp.H(Fr_tmp[0], CT.c_1, CT.c_2, CT.c_3);
        Mcl.mul(G_tmp[0], CT.c_1, sk.x_1_2);
        Mcl.mul(G_tmp[1], CT.c_2, sk.x_2_2);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        Mcl.mul(G_tmp[0], G_tmp[0], Fr_tmp[0]);
        Mcl.mul(G_tmp[1], CT.c_1, sk.x_1_1);
        Mcl.mul(G_tmp[2], CT.c_2, sk.x_2_1);
        Mcl.add(G_tmp[1], G_tmp[1], G_tmp[2]);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        if(!CT.c_4.equals(G_tmp[0])) throw new RuntimeException("wrong cipher text");
        Mcl.mul(G_tmp[0], CT.c_1, sk.x_1_3);
        Mcl.mul(G_tmp[1], CT.c_2, sk.x_2_3);
        Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
        Mcl.sub(G_tmp[0], CT.c_3, G_tmp[0]);
        PT.m = pp.Omega_inv(G_tmp[0]);
    }
}
