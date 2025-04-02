package PBCTest.CHTest;

import PBCTest.BasicParam;
import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.CH.CH_AMV_2017.PBC;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class CH_AMV_2017 extends BasicParam {
    double[] time_cost = new double[4];

    @BeforeAll
    static void initTest() {
        InitialLib();
        System.out.println("CH_AMV_2017");
        System.out.println("\t\t\tKeyGen, Hash, Check, Adapt");
    }

    @DisplayName("test CH_AMV_2017")
    @ParameterizedTest(name = "test curve {0} group {1}")
    @MethodSource("PBCTest.BasicParam#GetPBCCartesianProduct")
    void PBCTest(curve.PBC curve, Group group) {
        System.out.printf("%s.%s: ", curve, group);
        PBC scheme = new PBC();
        PBC.PublicParam pp = new PBC.PublicParam();
        scheme.SetUp(pp, curve, group);

        PBC.PublicKey[] pk = new PBC.PublicKey[repeat_cnt];
        PBC.SecretKey[] sk = new PBC.SecretKey[repeat_cnt];
        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        PBC.EncRandomness[] er = new PBC.EncRandomness[repeat_cnt];
        PBC.EncRandomness[] erp = new PBC.EncRandomness[repeat_cnt];
        Element[] m = new Element[repeat_cnt];
        Element[] m2 = new Element[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new PBC.PublicKey();
            sk[i] = new PBC.SecretKey();
            m[i] = pp.GetZrElement();
            m2[i] = pp.GetZrElement();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
            er[i] = new PBC.EncRandomness();
            erp[i] = new PBC.EncRandomness();
        }

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], er[i], r[i], pp, pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], er[i], pp, pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(erp[i], rp[i], h[i], er[i], pp, pk[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], erp[i], pp, pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @AfterEach
    void afterEach() {
        for (double x : time_cost) System.out.printf("%.6f, ", x);
        System.out.println();
    }
}
