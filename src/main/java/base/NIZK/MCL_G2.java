package base.NIZK;

import com.herumi.mcl.*;
import com.herumi.mcl.G2;
import utils.Func;
import utils.Hash;

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G2 {
    private static abstract class Proof {
        public void G(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }
    }

    public static class DL_Proof extends Proof {
        public G2 alpha = new G2();
        public Fr gamma = new Fr();

        public DL_Proof(Fr x, G2 g, G2 y) {
            this(x, g, y, new Fr[]{new Fr()});
        }

        public DL_Proof(Fr x, G2 g, G2 y, Fr[] Fr_tmp) {
            Mcl.mul(alpha, g, x);
            if(!y.equals(alpha)) throw new RuntimeException("wrong param, g^x != y");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.mul(alpha, g, Fr_tmp[0]);
            G(gamma, String.format("%s|%s", y, alpha));
            Mcl.mul(gamma, gamma, x);
            Mcl.add(gamma, gamma, Fr_tmp[0]);
        }

        public boolean Check(G2 g, G2 y) {
            return Check(g, y, new G2[]{new G2(), new G2()}, new Fr[]{new Fr()});
        }

        public boolean Check(G2 g, G2 y, G2[] G_tmp, Fr[] Fr_tmp) {
            Mcl.mul(G_tmp[0], g, gamma);
            Mcl.sub(G_tmp[0], G_tmp[0], alpha);
            G(Fr_tmp[0], String.format("%s|%s", y, alpha));
            Mcl.mul(G_tmp[1], y, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }

        public void CopyFrom(DL_Proof p) {
            this.alpha = p.alpha;
            this.gamma = p.gamma;
        }
    }

    public static class EQUAL_DL_Proof extends Proof {
        public G2 alpha_1 = new G2(), alpha_2 = new G2();
        public Fr gamma = new Fr();

        public EQUAL_DL_Proof(Fr x, G2 g_1, G2 y_1, G2 g_2, G2 y_2) {
            this(x, g_1, y_1, g_2, y_2, new Fr[]{new Fr()});
        }

        public EQUAL_DL_Proof(Fr x, G2 g_1, G2 y_1, G2 g_2, G2 y_2, Fr[] Fr_tmp) {
            Mcl.mul(alpha_1, g_1, x);
            if(!alpha_1.equals(y_1)) throw new RuntimeException("wrong param, g_1^x != y_1");
            Mcl.mul(alpha_1, g_2, x);
            if(!alpha_1.equals(y_2)) throw new RuntimeException("wrong param, g_2^x != y_2");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.mul(alpha_1, g_1, Fr_tmp[0]);
            Mcl.mul(alpha_2, g_2, Fr_tmp[0]);
            G(gamma, String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            Mcl.mul(gamma, gamma, x);
            Mcl.add(gamma, gamma, Fr_tmp[0]);
        }

        public boolean Check(G2 g_1, G2 y_1, G2 g_2, G2 y_2) {
            return Check(g_1, y_1, g_2, y_2, new G2[]{new G2(), new G2()}, new Fr[]{new Fr()});
        }

        public boolean Check(G2 g_1, G2 y_1, G2 g_2, G2 y_2, G2[] G_tmp, Fr[] Fr_tmp) {
            G(Fr_tmp[0], String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            Mcl.mul(G_tmp[0], g_1, gamma);
            Mcl.sub(G_tmp[0], G_tmp[0], alpha_1);
            Mcl.mul(G_tmp[1], y_1, Fr_tmp[0]);
            if(!G_tmp[0].equals(G_tmp[1])) return false;
            Mcl.mul(G_tmp[0], g_2, gamma);
            Mcl.sub(G_tmp[0], G_tmp[0], alpha_2);
            Mcl.mul(G_tmp[1], y_2, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }
    }

    public static class REPRESENT_Proof extends Proof {
        public G2 alpha = new G2();
        public Fr gamma_1 = new Fr(), gamma_2 = new Fr();

        public REPRESENT_Proof(G2 y, G2 g_1, Fr x_1, G2 g_2, Fr x_2) {
            this(y, g_1, x_1, g_2, x_2, new G2[]{new G2()}, new Fr[]{new Fr(), new Fr()});
        }

        public REPRESENT_Proof(G2 y, G2 g_1, Fr x_1, G2 g_2, Fr x_2, G2[] G_tmp, Fr[] Fr_tmp) {
            Mcl.mul(G_tmp[0], g_1, x_1);
            Mcl.mul(alpha, g_2, x_2);
            Mcl.add(G_tmp[0], G_tmp[0], alpha);
            if(!y.equals(G_tmp[0])) throw new RuntimeException("wrong param, y != g_1^x_1 * g_2^x_2");

            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Func.GetMCLZrRandomElement(Fr_tmp[1]);
            Mcl.mul(G_tmp[0], g_1, Fr_tmp[0]);
            Mcl.mul(alpha, g_2, Fr_tmp[1]);
            Mcl.add(alpha, G_tmp[0], alpha);
            Fr beta = new Fr();
            G(beta, String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            Mcl.mul(gamma_1, beta, x_1);
            Mcl.add(gamma_1, gamma_1, Fr_tmp[0]);

            Mcl.mul(gamma_2, beta, x_2);
            Mcl.add(gamma_2, gamma_2, Fr_tmp[1]);
        }

        public boolean Check(G2 y, G2 g_1, G2 g_2) {
            return Check(y, g_1, g_2, new G2[]{new G2(), new G2()}, new Fr[]{new Fr()});
        }

        public boolean Check(G2 y, G2 g_1, G2 g_2, G2[] G_tmp, Fr[] Fr_tmp) {
            Mcl.mul(G_tmp[0], g_1, gamma_1);
            Mcl.mul(G_tmp[1], g_2, gamma_2);
            Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);
            Mcl.sub(G_tmp[0], G_tmp[0], alpha);
            G(Fr_tmp[0], String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            Mcl.mul(G_tmp[1], y, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }
    }

    public static class DH_PAIR_Proof extends Proof {
        public Fr c = new Fr(), s = new Fr();

        public void H(Fr res, G2 m1, G2 m2, G2 m3, G2 m4, G2 m5, G2 m6) {
            Hash.H_MCL_Zr_1(res, String.format("%s|%s|%s|%s|%s|%s", m1, m2, m3, m4, m5, m6));
        }

        public DH_PAIR_Proof(Fr x, G2 g, G2 u, G2 h, G2 v) {
            this(x, g, u, h, v, new G2[]{new G2(), new G2(), new G2()}, new Fr[]{new Fr()});
        }

        public DH_PAIR_Proof(Fr x, G2 g, G2 u, G2 h, G2 v, G2[] G_tmp, Fr[] Fr_tmp) {
            Mcl.mul(G_tmp[0], g, x);
            Mcl.mul(G_tmp[1], h, x);
            if(!u.equals(G_tmp[0]) || !v.equals(G_tmp[1])) throw new RuntimeException("wrong param, u != g^x || v != h^x");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.mul(G_tmp[0], g, Fr_tmp[0]);
            Mcl.mul(G_tmp[1], h, Fr_tmp[0]);
            H(c, g, h, u, v, G_tmp[0], G_tmp[1]);
            Mcl.mul(s, c, x);
            Mcl.sub(s, Fr_tmp[0], s);
        }

        public boolean Check(G2 g, G2 u, G2 h, G2 v) {
            return Check(g, u, h, v, new G2[]{new G2(), new G2(), new G2()}, new Fr[]{new Fr()});
        }

        public boolean Check(G2 g, G2 u, G2 h, G2 v, G2[] G_tmp, Fr[] Fr_tmp) {
            Mcl.mul(G_tmp[0], g, s);
            Mcl.mul(G_tmp[1], u, c);
            Mcl.add(G_tmp[0], G_tmp[0], G_tmp[1]);

            Mcl.mul(G_tmp[1], h, s);
            Mcl.mul(G_tmp[2], v, c);
            Mcl.add(G_tmp[1], G_tmp[1], G_tmp[2]);
            H(Fr_tmp[0], g, h, u, v, G_tmp[0], G_tmp[1]);
            return c.equals(Fr_tmp[0]);
        }
    }
}
