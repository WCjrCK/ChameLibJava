package base.GroupParam.MCL;

import com.herumi.mcl.*;

import java.util.Random;

public class SingleGroup {
    public Fr GetZrElement() {
        Fr res = new Fr();
        res.setByCSPRNG();
        return res;
    }

    public static class SingleGroupG1 extends SingleGroup {
        public G1 GetGElement() {
            G1 res = new G1();
            byte[] m = new byte[128];
            Random random = new Random();
            random.nextBytes(m);
            Mcl.hashAndMapToG1(res, m);
            return res;
        }
    }

    public static class SingleGroupG2 extends SingleGroup {
        public G2 GetGElement() {
            G2 res = new G2();
            byte[] m = new byte[128];
            Random random = new Random();
            random.nextBytes(m);
            Mcl.hashAndMapToG2(res, m);
            return res;
        }
    }

//    public static class SingleGroupGT extends SingleGroup {
//        public GT GetGElement() {
//            GT res = new GT();
//            byte[] m = new byte[128];
//            Random random = new Random();
//            G1 g1 = new G1();
//            random.nextBytes(m);
//            Mcl.hashAndMapToG1(g1, m);
//            G2 g2 = new G2();
//            random.nextBytes(m);
//            Mcl.hashAndMapToG2(g2, m);
//            Mcl.pairing(res, g1, g2);
//            return res;
//        }
//    }
}

