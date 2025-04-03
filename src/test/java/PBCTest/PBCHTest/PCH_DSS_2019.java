package PBCTest.PBCHTest;

import PBCTest.BasicParam;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.PCH_DSS_2019.PBC;
import utils.BooleanFormulaParser;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class PCH_DSS_2019 extends BasicParam {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        System.out.println("PCH_DSS_2019");
        System.out.println("\t\t\tSetUp, KeyGen, Hash, Check, Adapt");
    }

    @DisplayName("test PCH_DSS_2019")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2}")
    @MethodSource("PBCTest.BasicParam#GetPBCInvertk")
    void PBCTest(curve.PBC curve, boolean swap_G1G2, int k) {
        System.out.printf("%s (k: %d, swap: %b): ", curve, k, swap_G1G2);
        PBC scheme = new PBC(k);
        PBC.PublicParam pp = new PBC.PublicParam(curve, swap_G1G2);
        PBC.MasterPublicKey mpk = new PBC.MasterPublicKey();
        PBC.MasterSecretKey msk = new PBC.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(mpk, msk, pp);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.PBC LSSS = new base.LSSS.PBC();
        base.LSSS.PBC.Matrix[] MSP = new base.LSSS.PBC.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];

        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];


        PBC.SecretKey[] sk = new PBC.SecretKey[repeat_cnt];
        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.PBC.Matrix(pp.GP.Zr);
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));

            sk[i] = new PBC.SecretKey();
            m[i] = pp.GP.GetZrElement().toString();
            m2[i] = pp.GP.GetZrElement().toString();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(sk[i], pp, mpk, msk, S[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, mpk, MSP[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], mpk, m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, mpk, MSP[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], mpk, m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @AfterEach
    void afterEach() {
        for (double x : time_cost) System.out.printf("%.6f, ", x);
        System.out.println();
    }
}
