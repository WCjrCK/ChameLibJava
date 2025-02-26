package base.NIZK;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;
import utils.Func;
import utils.Hash;

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G2 {
    private static abstract class Proof {
        public Fr G(String m) {
            return Hash.H_MCL_Zr_1(m);
        }
    }

    public static class DL_Proof extends Proof {
        public G2 alpha = new G2();
        public Fr gamma = new Fr();

        public DL_Proof(Fr x, G2 g, G2 y) {
            G2 tmp = new G2();
            Mcl.mul(tmp, g, x);
            if(!y.equals(tmp)) throw new RuntimeException("wrong param, g^x != y");
            Fr a = Func.GetMCLZrRandomElement();
            Mcl.mul(alpha, g, a);
            Mcl.mul(gamma, G(String.format("%s|%s", y, alpha)), x);
            Mcl.add(gamma, gamma, a);
        }

        public boolean Check(G2 g, G2 y) {
            G2 tmp1 = new G2();
            Mcl.mul(tmp1, g, gamma);
            Mcl.sub(tmp1, tmp1, alpha);
            G2 tmp2 = new G2();
            Mcl.mul(tmp2, y, G(String.format("%s|%s", y, alpha)));
            return tmp1.equals(tmp2);
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
            G2 tmp = new G2();
            Mcl.mul(tmp, g_1, x);
            if(!tmp.equals(y_1)) throw new RuntimeException("wrong param, g_1^x != y_1");
            Mcl.mul(tmp, g_2, x);
            if(!tmp.equals(y_2)) throw new RuntimeException("wrong param, g_2^x != y_2");
            Fr a = Func.GetMCLZrRandomElement();
            Mcl.mul(alpha_1, g_1, a);
            Mcl.mul(alpha_2, g_2, a);
            Mcl.mul(gamma, G(String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2)), x);
            Mcl.add(gamma, gamma, a);
        }

        public boolean Check(G2 g_1, G2 y_1, G2 g_2, G2 y_2) {
            Fr beta = G(String.format("%s|%s|%s|%s", y_1, y_2, alpha_1, alpha_2));
            G2 tmp1 = new G2();
            Mcl.mul(tmp1, g_1, gamma);
            Mcl.sub(tmp1, tmp1, alpha_1);
            G2 tmp2 = new G2();
            Mcl.mul(tmp2, y_1, beta);
            if(!tmp1.equals(tmp2)) return false;
            Mcl.mul(tmp1, g_2, gamma);
            Mcl.sub(tmp1, tmp1, alpha_2);
            Mcl.mul(tmp2, y_2, beta);
            return tmp1.equals(tmp2);
        }
    }

    public static class REPRESENT_Proof extends Proof {
        public G2 alpha = new G2();
        public Fr gamma_1 = new Fr(), gamma_2 = new Fr();

        public REPRESENT_Proof(G2 y, G2 g_1, Fr x_1, G2 g_2, Fr x_2) {
            G2 tmp1 = new G2();
            Mcl.mul(tmp1, g_1, x_1);
            G2 tmp2 = new G2();
            Mcl.mul(tmp2, g_2, x_2);
            Mcl.add(tmp1, tmp1, tmp2);
            if(!y.equals(tmp1)) throw new RuntimeException("wrong param, y != g_1^x_1 * g_2^x_2");

            Fr a_1 = Func.GetMCLZrRandomElement();
            Fr a_2 = Func.GetMCLZrRandomElement();
            Mcl.mul(tmp1, g_1, a_1);
            Mcl.mul(tmp2, g_2, a_2);
            Mcl.add(alpha, tmp1, tmp2);
            Fr beta = G(String.format("%s|%s|%s|%s", y, g_1, g_2, alpha));
            Mcl.mul(gamma_1, beta, x_1);
            Mcl.add(gamma_1, gamma_1, a_1);

            Mcl.mul(gamma_2, beta, x_2);
            Mcl.add(gamma_2, gamma_2, a_2);
        }

        public boolean Check(G2 y, G2 g_1, G2 g_2) {
            G2 tmp1 = new G2();
            Mcl.mul(tmp1, g_1, gamma_1);
            G2 tmp2 = new G2();
            Mcl.mul(tmp2, g_2, gamma_2);
            Mcl.add(tmp1, tmp1, tmp2);
            Mcl.sub(tmp1, tmp1, alpha);
            Mcl.mul(tmp2, y, G(String.format("%s|%s|%s|%s", y, g_1, g_2, alpha)));
            return tmp1.equals(tmp2);
        }
    }
}
