package scheme.CH.CH_KEF_DLP_LLA_2012;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G2 {
    public static class Label {
        public G2 L = new G2(), R = new G2();
    }

    public static class LabelGen {
        public G2 y_1 = new G2(), omega_1 = new G2();
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
            G2 t = pp.GP.GetGElement();
            Fr H2_t = pp.H2(t);
            LabelGen lg = Dict.get(pk.toString());
            Mcl.mul(L.L, lg.y_1, H2_t);
            Mcl.mul(L.R, lg.omega_1, H2_t);
            Mcl.add(L.R, L.R, t);
        }
    }

    public static class PublicParam {
        public base.GroupParam.MCL.SingleGroup.SingleGroupG2 GP;

        public PublicParam() {
            GP = new base.GroupParam.MCL.SingleGroup.SingleGroupG2();
        }

        public Fr H1(G2 m1, G2 m2, G2 m3) {
            return Hash.H_MCL_Zr_1(String.format("%s|%s|%s", m1, m2, m3));
        }

        public Fr H2(G2 m1) {
            return Hash.H_MCL_Zr_1(m1.toString());
        }
    }

    public static class PublicKey {
        public G2 g, y_2 = new G2();

        public String toString() {
            return String.format("%s|%s", g, y_2);
        }
    }

    public static class SecretKey {
        public Fr alpha, x_1, x_2;
    }

    public static class HashValue {
        public G2 S = new G2();
    }

    public static class Randomness {
        Fr r = new Fr();
    }

    private void getHashValue(G2 res, Randomness r, Label L, PublicParam PP, PublicKey pk, Fr m) {
        G2 tmp1 = new G2();
        Mcl.mul(res, pk.g, m);
        Mcl.mul(tmp1, pk.y_2, PP.H1(L.L, L.R, L.L));
        Mcl.add(tmp1, tmp1, L.L);
        Mcl.mul(tmp1, tmp1, r.r);
        Mcl.add(res, res, tmp1);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP, LabelManager LM) {
        pk.g = PP.GP.GetGElement();
        sk.alpha = PP.GP.GetZrElement();
        sk.x_1 = PP.GP.GetZrElement();
        sk.x_2 = PP.GP.GetZrElement();
        LabelGen lg = new LabelGen();
        Mcl.mul(lg.y_1, pk.g, sk.x_1);
        Mcl.mul(lg.omega_1, lg.y_1, sk.alpha);
        Mcl.mul(pk.y_2, pk.g, sk.x_2);
        LM.add(pk, lg);
    }

    public void Hash(HashValue h, Randomness r, Label L, PublicParam PP, LabelManager LM, PublicKey pk, Fr m) {
        LM.get(L, pk);
        r.r = PP.GP.GetZrElement();
        getHashValue(h.S, r, L, PP, pk, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Label L, Fr m) {
        G2 tmp = new G2();
        getHashValue(tmp, r, L, PP, pk, m);
        return h.S.equals(tmp);
    }

    public void UForge(Randomness r_p, HashValue h, Randomness r, Label L, PublicParam PP, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if (!Check(h, r, PP, pk, L, m)) throw new RuntimeException("illegal hash");
        G2 t = new G2();
        Mcl.mul(t, L.L, sk.alpha);
        Mcl.sub(t, L.R, t);

        Fr H2_t = PP.H2(t);

        G2 tmp = new G2();
        Fr tmp1 = new Fr();
        Mcl.mul(tmp1, sk.x_1, H2_t);
        Mcl.mul(tmp, pk.g, tmp1);
        if (!tmp.equals(L.L)) throw new RuntimeException("illegal label");

        Fr c = PP.H1(L.L, L.R, L.L);
        Fr tmp2 = new Fr();
        Mcl.mul(tmp2, sk.x_2, c);
        Mcl.add(tmp2, tmp1, tmp2);
        Mcl.sub(tmp1, m, m_p);
        Mcl.div(tmp1, tmp1, tmp2);
        Mcl.add(r_p.r, r.r, tmp1);
    }

    public void IForge(Randomness r_pp, Randomness r, Randomness r_p, Fr m, Fr m_p, Fr m_pp) {
        Fr tmp1 = new Fr();
        Mcl.sub(tmp1, r_p.r, r.r);
        Fr tmp2 = new Fr();
        Mcl.sub(tmp2, m_p, m_pp);
        Mcl.mul(tmp1, tmp1, tmp2);
        Mcl.sub(tmp2, m, m_p);
        Mcl.div(tmp1, tmp1, tmp2);
        Mcl.add(r_pp.r, r_p.r, tmp1);
    }
}
