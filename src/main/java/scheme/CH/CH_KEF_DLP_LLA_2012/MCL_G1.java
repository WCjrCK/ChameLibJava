package scheme.CH.CH_KEF_DLP_LLA_2012;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings({"DuplicatedCode", "SuspiciousNameCombination"})
public class MCL_G1 {
    public static class Label {
        public G1 L = new G1(), R = new G1();
    }

    public static class LabelGen {
        public G1 y_1 = new G1(), omega_1 = new G1();
    }

    public static class LabelManager {
        public Map<String, LabelGen> Dict = new HashMap<>();
        public PublicParam pp;

        public LabelManager(PublicParam pp) {
            this.pp = pp;
        }

        public void add(PublicKey pk, LabelGen lg) {
            Dict.put(pk.toString(), lg);
        }

        public void get(Label L, PublicKey pk) {
            get(L, pk, new G1[]{new G1()}, new Fr[]{new Fr()});
        }

        public void get(Label L, PublicKey pk, G1[] G_tmp, Fr[] Fr_tmp) {
            pp.GP.GetGElement(G_tmp[0]);
            pp.H2(Fr_tmp[0], G_tmp[0]);
            LabelGen lg = Dict.get(pk.toString());
            Mcl.mul(L.L, lg.y_1, Fr_tmp[0]);
            Mcl.mul(L.R, lg.omega_1, Fr_tmp[0]);
            Mcl.add(L.R, G_tmp[0], L.R);
            System.out.println("target:");
            System.out.println("g ^ x1: " + lg.y_1);
            System.out.println("H2(t): " + Fr_tmp[0]);
            System.out.println("(g ^ x1) ^ H2(t) = L: " + L.L);
            System.out.println("t: " + G_tmp[0]);
            System.out.println("R: " + L.R);
            System.out.println();
        }
    }

    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();

        public void H1(Fr res, G1 m1, G1 m2, G1 m3) {
            Hash.H_MCL_Zr_1(res, String.format("%s|%s|%s", m1, m2, m3));
        }

        public void H2(Fr res, G1 m1) {
            Hash.H_MCL_Zr_1(res, m1.toString());
        }
    }

    public static class PublicKey {
        public G1 g = new G1(), y_2 = new G1();

        public String toString() {
            return String.format("%s|%s", g, y_2);
        }
    }

    public static class SecretKey {
        public Fr alpha = new Fr(), x_1 = new Fr(), x_2 = new Fr();
    }

    public static class HashValue {
        public G1 S = new G1();
    }

    public static class Randomness {
        Fr r = new Fr();
    }

    private final G1[] G_tmp = new G1[]{new G1(), new G1()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr()};

    private void getHashValue(G1 res, Randomness r, Label L, PublicParam PP, PublicKey pk, Fr m) {
        Mcl.mul(res, pk.g, m);
        PP.H1(Fr_tmp[0], L.L, L.R, L.L);
        Mcl.mul(G_tmp[0], pk.y_2, Fr_tmp[0]);
        Mcl.add(G_tmp[0], G_tmp[0], L.L);
        Mcl.mul(G_tmp[0], G_tmp[0], r.r);
        Mcl.add(res, res, G_tmp[0]);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP, LabelManager LM) {
        PP.GP.GetGElement(pk.g);
        PP.GP.GetZrElement(sk.alpha);
        PP.GP.GetZrElement(sk.x_1);
        PP.GP.GetZrElement(sk.x_2);
        LabelGen lg = new LabelGen();
        Mcl.mul(lg.y_1, pk.g, sk.x_1);
        Mcl.mul(pk.y_2, pk.g, sk.x_2);

        Mcl.mul(lg.omega_1, lg.y_1, sk.alpha);
        LM.add(pk, lg);
    }

    public void Hash(HashValue h, Randomness r, Label L, PublicParam PP, LabelManager LM, PublicKey pk, Fr m) {
        LM.get(L, pk, G_tmp, Fr_tmp);
        PP.GP.GetZrElement(r.r);
        getHashValue(h.S, r, L, PP, pk, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Label L, Fr m) {
        getHashValue(G_tmp[1], r, L, PP, pk, m);
        return h.S.equals(G_tmp[1]);
    }

    public void UForge(Randomness r_p, HashValue h, Randomness r, Label L, PublicParam PP, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if (!Check(h, r, PP, pk, L, m)) throw new RuntimeException("illegal hash");
        Mcl.mul(G_tmp[0], L.L, sk.alpha);
        Mcl.sub(G_tmp[0], L.R, G_tmp[0]);

        System.out.println("UForge");
        System.out.println("L: " + L.L);
        System.out.println("R: " + L.R);
        System.out.println("t: " + G_tmp[0]);

        PP.H2(Fr_tmp[0], G_tmp[0]);

        Mcl.mul(G_tmp[0], pk.g, sk.x_1);
        System.out.println("g: " + pk.g);
        System.out.println("x1: " + sk.x_1);
        System.out.println("g ^ x1: " + G_tmp[0]);
        System.out.println("H2(t): " + Fr_tmp[0]);
        Mcl.mul(G_tmp[0], G_tmp[0], Fr_tmp[0]);
        Mcl.mul(Fr_tmp[0], sk.x_1, Fr_tmp[0]);
        System.out.println("x1 * H2(t): " + Fr_tmp[0]);
        System.out.println("(g ^ x1) ^ H2(t): " + G_tmp[0]);
        Mcl.mul(G_tmp[0], pk.g, Fr_tmp[0]);
        System.out.println("g ^ {x1 * H2(t)}: " + G_tmp[0]);
        if (!G_tmp[0].equals(L.L)) throw new RuntimeException("illegal label");

        PP.H1(Fr_tmp[1], L.L, L.R, L.L);
        Mcl.mul(Fr_tmp[1], sk.x_2, Fr_tmp[1]);
        Mcl.add(Fr_tmp[1], Fr_tmp[0], Fr_tmp[1]);
        Mcl.sub(r_p.r, m, m_p);
        Mcl.div(r_p.r, r_p.r, Fr_tmp[1]);
        Mcl.add(r_p.r, r.r, r_p.r);
    }

    public void IForge(Randomness r_pp, Randomness r, Randomness r_p, Fr m, Fr m_p, Fr m_pp) {
        Mcl.sub(r_pp.r, r_p.r, r.r);
        Mcl.sub(Fr_tmp[0], m_p, m_pp);
        Mcl.mul(r_pp.r, r_pp.r, Fr_tmp[0]);
        Mcl.sub(Fr_tmp[0], m, m_p);
        Mcl.div(r_pp.r, r_pp.r, Fr_tmp[0]);
        Mcl.add(r_pp.r, r_p.r, r_pp.r);
    }
}
