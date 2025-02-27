package base.GroupParam.MCL;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import utils.Func;

public class SingleGroup {
    public void GetZrElement(Fr res) {
        Func.GetMCLZrRandomElement(res);
    }

    public static class SingleGroupG1 extends SingleGroup {
        public void GetGElement(G1 res) {
            Func.GetMCLG1RandomElement(res);
        }
    }

    public static class SingleGroupG2 extends SingleGroup {
        public void GetGElement(G2 res) {
            Func.GetMCLG2RandomElement(res);
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

