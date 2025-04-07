package base.NIZK;

import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Func;
import utils.Hash;

@SuppressWarnings({"unused", "SuspiciousNameCombination"})
public class MCL_GT {
    private static abstract class Proof {
        public void G(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }
    }

    public static class DL_Proof extends Proof {
        public GT alpha = new GT();
        public Fr gamma = new Fr();

        public DL_Proof(Fr x, GT g, GT y) {
            this(x, g, y, new Fr[]{new Fr()});
        }

        public DL_Proof(Fr x, GT g, GT y, Fr[] Fr_tmp) {
            Mcl.pow(alpha, g, x);
            if(!y.equals(alpha)) throw new RuntimeException("wrong param, g^x != y");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.pow(alpha, g, Fr_tmp[0]);
            G(gamma, String.format("%s|%s", y, alpha));
            Mcl.mul(gamma, gamma, x);
            Mcl.add(gamma, gamma, Fr_tmp[0]);
        }

        public boolean Check(GT g, GT y) {
            return Check(g, y, new GT[]{new GT(), new GT()}, new Fr[]{new Fr()});
        }

        public boolean Check(GT g, GT y, GT[] G_tmp, Fr[] Fr_tmp) {
            Mcl.pow(G_tmp[0], g, gamma);
            Mcl.inv(G_tmp[1], alpha);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
            G(Fr_tmp[0], String.format("%s|%s", y, alpha));
            Mcl.pow(G_tmp[1], y, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }

        public void CopyFrom(DL_Proof p) {
            this.alpha = p.alpha;
            this.gamma = p.gamma;
        }
    }

    public static class EQUAL_DL_Proof extends Proof {
        public GT alpha_1 = new GT(), alpha_2 = new GT();
        public Fr gamma = new Fr();

        public EQUAL_DL_Proof(Fr x, GT g_1, GT y_1, GT g_2, GT y_2) {
            this(x, g_1, y_1, g_2, y_2, new Fr[]{new Fr()});
        }

        public EQUAL_DL_Proof(Fr x, GT g_1, GT y_1, GT g_2, GT y_2, Fr[] Fr_tmp) {
            Mcl.pow(alpha_1, g_1, x);
            if(!alpha_1.equals(y_1)) throw new RuntimeException("wrong param, g_1^x != y_1");
            Mcl.pow(alpha_1, g_2, x);
            if(!alpha_1.equals(y_2)) throw new RuntimeException("wrong param, g_2^x != y_2");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.pow(alpha_1, g_1, Fr_tmp[0]);
            Mcl.pow(alpha_2, g_2, Fr_tmp[0]);
            G(gamma, String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            Mcl.mul(gamma, gamma, x);
            Mcl.add(gamma, gamma, Fr_tmp[0]);
        }

        public boolean Check(GT g_1, GT y_1, GT g_2, GT y_2) {
            return Check(g_1, y_1, g_2, y_2, new GT[]{new GT(), new GT()}, new Fr[]{new Fr()});
        }

        public boolean Check(GT g_1, GT y_1, GT g_2, GT y_2, GT[] G_tmp, Fr[] Fr_tmp) {
            G(Fr_tmp[0], String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            Mcl.pow(G_tmp[0], g_1, gamma);
            Mcl.inv(G_tmp[1], alpha_1);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
            Mcl.pow(G_tmp[1], y_1, Fr_tmp[0]);
            if(!G_tmp[0].equals(G_tmp[1])) return false;
            Mcl.pow(G_tmp[0], g_2, gamma);
            Mcl.inv(G_tmp[1], alpha_2);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
            Mcl.pow(G_tmp[1], y_2, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }
    }

    public static class REPRESENT_Proof extends Proof {
        public GT alpha = new GT();
        public Fr gamma_1 = new Fr(), gamma_2 = new Fr();

        public REPRESENT_Proof(GT y, GT g_1, Fr x_1, GT g_2, Fr x_2) {
            this(y, g_1, x_1, g_2, x_2, new GT[]{new GT()}, new Fr[]{new Fr(), new Fr()});
        }

        public REPRESENT_Proof(GT y, GT g_1, Fr x_1, GT g_2, Fr x_2, GT[] G_tmp, Fr[] Fr_tmp) {
            Mcl.pow(G_tmp[0], g_1, x_1);
            Mcl.pow(alpha, g_2, x_2);
            Mcl.mul(G_tmp[0], G_tmp[0], alpha);
            if(!y.equals(G_tmp[0])) throw new RuntimeException("wrong param, y != g_1^x_1 * g_2^x_2");

            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Func.GetMCLZrRandomElement(Fr_tmp[1]);
            Mcl.pow(G_tmp[0], g_1, Fr_tmp[0]);
            Mcl.pow(alpha, g_2, Fr_tmp[1]);
            Mcl.mul(alpha, G_tmp[0], alpha);
            Fr beta = new Fr();
            G(beta, String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            Mcl.mul(gamma_1, beta, x_1);
            Mcl.add(gamma_1, gamma_1, Fr_tmp[0]);

            Mcl.mul(gamma_2, beta, x_2);
            Mcl.add(gamma_2, gamma_2, Fr_tmp[1]);
        }

        public boolean Check(GT y, GT g_1, GT g_2) {
            return Check(y, g_1, g_2, new GT[]{new GT(), new GT()}, new Fr[]{new Fr()});
        }

        public boolean Check(GT y, GT g_1, GT g_2, GT[] G_tmp, Fr[] Fr_tmp) {
            Mcl.pow(G_tmp[0], g_1, gamma_1);
            Mcl.pow(G_tmp[1], g_2, gamma_2);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
            Mcl.inv(G_tmp[1], alpha);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);
            G(Fr_tmp[0], String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            Mcl.pow(G_tmp[1], y, Fr_tmp[0]);
            return G_tmp[0].equals(G_tmp[1]);
        }
    }

    public static class DH_PAIR_Proof extends Proof {
        public Fr c = new Fr(), s = new Fr();

        public void H(Fr res, GT m1, GT m2, GT m3, GT m4, GT m5, GT m6) {
            Hash.H_MCL_Zr_1(res, String.format("%s|%s|%s|%s|%s|%s", m1, m2, m3, m4, m5, m6));
        }

        public DH_PAIR_Proof(Fr x, GT g, GT u, GT h, GT v) {
            this(x, g, u, h, v, new GT[]{new GT(), new GT(), new GT()}, new Fr[]{new Fr()});
        }

        public DH_PAIR_Proof(Fr x, GT g, GT u, GT h, GT v, GT[] G_tmp, Fr[] Fr_tmp) {
            Mcl.pow(G_tmp[0], g, x);
            Mcl.pow(G_tmp[1], h, x);
            if(!u.equals(G_tmp[0]) || !v.equals(G_tmp[1])) throw new RuntimeException("wrong param, u != g^x || v != h^x");
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Mcl.pow(G_tmp[0], g, Fr_tmp[0]);
            Mcl.pow(G_tmp[1], h, Fr_tmp[0]);
            H(c, g, h, u, v, G_tmp[0], G_tmp[1]);
            Mcl.mul(s, c, x);
            Mcl.sub(s, Fr_tmp[0], s);
        }

        public boolean Check(GT g, GT u, GT h, GT v) {
            return Check(g, u, h, v, new GT[]{new GT(), new GT(), new GT()}, new Fr[]{new Fr()});
        }

        public boolean Check(GT g, GT u, GT h, GT v, GT[] G_tmp, Fr[] Fr_tmp) {
            Mcl.pow(G_tmp[0], g, s);
            Mcl.pow(G_tmp[1], u, c);
            Mcl.mul(G_tmp[0], G_tmp[0], G_tmp[1]);

            Mcl.pow(G_tmp[1], h, s);
            Mcl.pow(G_tmp[2], v, c);
            Mcl.mul(G_tmp[1], G_tmp[1], G_tmp[2]);
            H(Fr_tmp[0], g, h, u, v, G_tmp[0], G_tmp[1]);
            return c.equals(Fr_tmp[0]);
        }
    }
}
