import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static utils.Func.InitialLib;

public class PBCHTest {
    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test LSSS Native impl")
    @Test
    void LSSSNativeTest() {
        base.LSSS.Native lsss_gen =  new base.LSSS.Native();
        base.LSSS.Native.Matrix mat =  new base.LSSS.Native.Matrix();
        base.LSSS.Native.PolicyList pi =  new base.LSSS.Native.PolicyList();
//        lsss_gen.GenLSSSMatrices(mat, pi, "P555&(((P1&P2)|(P3&P4))|((P1|P2)&(P3|P4)))");
//        lsss_gen.GenLSSSMatrices(mat, pi, "P555");
        lsss_gen.GenLSSSMatrices(mat, pi, "A&(DDDD|(BB&CCC))");
//        lsss_gen.GenLSSSMatrices(mat, pi, "A&(D|(B&C))");
//        lsss_gen.GenLSSSMatrices(mat, pi, "A&D&B&C");
        mat.Print();
        pi.Print();
    }
}
