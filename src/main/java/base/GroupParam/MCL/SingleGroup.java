package base.GroupParam.MCL;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.GT;
import utils.Func;

@SuppressWarnings("unused")
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

    public static class SingleGroupGT extends SingleGroup {
        public void GetGElement(GT res) {
            Func.GetMCLGTRandomElement(res);
        }
    }
}

