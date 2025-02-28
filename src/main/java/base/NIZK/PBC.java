package base.NIZK;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import utils.Hash;

@SuppressWarnings("rawtypes")
public class PBC {
    private static abstract class Proof {
        public Field Zr;

        public Element G(String m) {
            return Hash.H_String_1_PBC_1(Zr, m);
        }

        public Proof(Field Zr) {
            this.Zr = Zr;
        }
    }

    public static class DL_Proof extends Proof {
        public Element alpha, gamma;

        public DL_Proof(Field Zr, Element x, Element g, Element y) {
            super(Zr);
            if(!g.powZn(x).isEqual(y)) throw new RuntimeException("wrong param, g^x != y");
            gamma = this.Zr.newRandomElement().getImmutable();
            alpha = g.powZn(gamma);
            gamma = G(String.format("%s|%s", y, alpha)).mul(x).add(gamma).getImmutable();
        }

        public boolean Check(Element g, Element y) {
            return g.powZn(gamma).div(alpha).isEqual(y.powZn(G(String.format("%s|%s", y, alpha))));
        }

        public void CopyFrom(DL_Proof p) {
            this.Zr = p.Zr;
            this.alpha = p.alpha;
            this.gamma = p.gamma;
        }
    }

    public static class EQUAL_DL_Proof extends Proof {
        public Element alpha_1, alpha_2, gamma;

        public EQUAL_DL_Proof(Field G, Element x, Element g_1, Element y_1, Element g_2, Element y_2) {
            super(G);
            if(!g_1.powZn(x).isEqual(y_1)) throw new RuntimeException("wrong param, g_1^x != y_1");
            if(!g_2.powZn(x).isEqual(y_2)) throw new RuntimeException("wrong param, g_2^x != y_2");
            gamma = Zr.newRandomElement().getImmutable();
            alpha_1 = g_1.powZn(gamma);
            alpha_2 = g_2.powZn(gamma);
            gamma = G(String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2)).mul(x).add(gamma).getImmutable();
        }

        public boolean Check(Element g_1, Element y_1, Element g_2, Element y_2) {
            Element beta = G(String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            return g_1.powZn(gamma).div(alpha_1).isEqual(y_1.powZn(beta)) && g_2.powZn(gamma).div(alpha_2).isEqual(y_2.powZn(beta));
        }
    }

    public static class REPRESENT_Proof extends Proof {
        public Element alpha, gamma_1, gamma_2;

        public REPRESENT_Proof(Field Zr, Element y, Element g_1, Element x_1, Element g_2, Element x_2) {
            super(Zr);
            if(!y.isEqual(g_1.powZn(x_1).mul(g_2.powZn(x_2)))) throw new RuntimeException("wrong param, y != g_1^x_1 * g_2^x_2");
            gamma_1 = this.Zr.newRandomElement().getImmutable();
            gamma_2 = this.Zr.newRandomElement().getImmutable();
            alpha = g_1.powZn(gamma_1).mul(g_2.powZn(gamma_2));
            Element beta = G(String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            gamma_1 = beta.mul(x_1).add(gamma_1).getImmutable();
            gamma_2 = beta.mul(x_2).add(gamma_2).getImmutable();
        }

        public boolean Check(Element y, Element g_1, Element g_2) {
            return g_1.powZn(gamma_1).mul(g_2.powZn(gamma_2)).div(alpha).isEqual(y.powZn(G(String.format("%s|%s|%s|%s", y, g_1, g_2, alpha))));
        }
    }

    public static class DH_PAIR_Proof extends Proof {
        public Element c, s;

        public Element H(Element m1, Element m2, Element m3, Element m4, Element m5, Element m6) {
            return Hash.H_String_1_PBC_1(Zr, String.format("%s|%s|%s|%s|%s|%s", m1, m2, m3, m4, m5, m6));
        }

        public DH_PAIR_Proof(Field Zr, Element x, Element g, Element u, Element h, Element v) {
            super(Zr);
            if(!u.isEqual(g.powZn(x)) || !v.isEqual(h.powZn(x))) throw new RuntimeException("wrong param, u != g^x || v != h^x");
            s = Zr.newRandomElement().getImmutable();
            c = H(g, h, u, v, g.powZn(s), h.powZn(s));
            s = s.sub(c.mul(x)).getImmutable();
        }

        public boolean Check(Element g, Element u, Element h, Element v) {
            return c.isEqual(H(g, h, u, v, g.powZn(s).mul(u.powZn(c)), h.powZn(s).mul(v.powZn(c))));
        }
    }
}
