package scheme.CH.CH_KEF_DLP_LLA_2012;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;

import java.util.HashMap;
import java.util.Map;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P4. CH_inf: a key exposure free chameleon hash scheme
 */

public class PBC {
    public static class Label {
        public Element L, R;
    }

    public static class LabelGen {
        public Element y_1, omega_1;
    }

    public static class LabelManager {
        public Map<PublicKey, LabelGen> Dict = new HashMap<>();
        public PublicParam pp;

        public LabelManager(PublicParam pp) {
            this.pp = pp;
        }

        public void add(PublicKey pk, LabelGen lg) {
            Dict.put(pk, lg);
        }

        public void get(Label L, PublicKey pk) {
            Element t = pp.GP.G.newRandomElement().getImmutable();
            Element H2_t = pp.H2(t);
            LabelGen lg = Dict.get(pk);
            L.L = lg.y_1.powZn(H2_t).getImmutable();
            L.R = t.mul(lg.omega_1.powZn(H2_t)).getImmutable();
        }
    }

    public static class PublicParam {
        public base.GroupParam.PBC.SingleGroup GP;

        public PublicParam(curve.PBC curve, Group group) {
            GP = new base.GroupParam.PBC.SingleGroup(curve, group);
        }

        public Element H1(Element m1, Element m2, Element m3) {
            return Hash.H_PBC_3_1(GP.Zr, m1, m2, m3);
        }

        public Element H2(Element m1) {
            return Hash.H_PBC_1_1(GP.Zr, m1);
        }
    }

    public static class PublicKey {
        public Element g, y_2;
    }

    public static class SecretKey {
        public Element alpha, x_1, x_2;
    }

    public static class HashValue {
        public Element S;
    }

    public static class Randomness {
        Element r;
    }

    private Element getHashValue(Randomness r, Label L, PublicParam PP, PublicKey pk, Element m) {
        return pk.g.powZn(m).mul(L.L.mul(pk.y_2.powZn(PP.H1(L.L, L.R, L.L))).powZn(r.r)).getImmutable();
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam PP, LabelManager LM) {
        pk.g = PP.GP.GetGElement();
        sk.alpha = PP.GP.GetZrElement();
        sk.x_1 = PP.GP.GetZrElement();
        sk.x_2 = PP.GP.GetZrElement();
        LabelGen lg = new LabelGen();
        lg.y_1 = pk.g.powZn(sk.x_1).getImmutable();
        lg.omega_1 = lg.y_1.powZn(sk.alpha).getImmutable();
        pk.y_2 = pk.g.powZn(sk.x_2).getImmutable();
        LM.add(pk, lg);
    }

    public void Hash(HashValue h, Randomness r, Label L, PublicParam PP, LabelManager LM, PublicKey pk, Element m) {
        LM.get(L, pk);
        r.r = PP.GP.GetZrElement();
        h.S = getHashValue(r, L, PP, pk, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicParam PP, PublicKey pk, Label L, Element m) {
        return h.S.isEqual(getHashValue(r, L, PP, pk, m));
    }

    public void UForge(Randomness r_p, HashValue h, Randomness r, Label L, PublicParam PP, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(h, r, PP, pk, L, m)) throw new RuntimeException("illegal hash");
        Element t = L.R.div(L.L.powZn(sk.alpha)).getImmutable();
        Element H2_t = PP.H2(t), c = PP.H1(L.L, L.R, L.L);
        if(!pk.g.powZn(H2_t.mul(sk.x_1)).isEqual(L.L)) throw new RuntimeException("illegal label");
        r_p.r = r.r.add(m.sub(m_p).div(sk.x_1.mul(H2_t).add(sk.x_2.mul(c))));
    }

    public void IForge(Randomness r_pp, Randomness r, Randomness r_p, Element m, Element m_p, Element m_pp) {
        r_pp.r = r_p.r.add(r_p.r.sub(r.r).mul(m_p.sub(m_pp)).div(m.sub(m_p)));
    }
}
