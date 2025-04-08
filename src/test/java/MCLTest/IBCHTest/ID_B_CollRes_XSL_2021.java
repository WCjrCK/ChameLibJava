package MCLTest.IBCHTest;

import MCLTest.BasicParam;
import com.herumi.mcl.Fr;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.IBCH.ID_B_CollRes_XSL_2021.MCL;
import scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class ID_B_CollRes_XSL_2021 extends BasicParam {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/IBCH/ID_B_CollRes_XSL_2021.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("ID_B_CollRes_XSL_2021\t\t\tSetUp, KeyGen, Hash, Check, Adapt\n");
            System.out.println("ID_B_CollRes_XSL_2021");
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test ID_B_CollRes_XSL_2021")
    @ParameterizedTest(name = "test curve {0}, Identity len = {1}, swap_G1G2 false")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertIdentityLen")
    void MCLTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|ID len:%d|swap:false: ", curve, n));
            System.out.printf("curve:%s (ID len: %d, swap: false): ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL scheme = new MCL();
        MCL.PublicParam pp = new MCL.PublicParam(n);
        MCL.MasterSecretKey msk = new MCL.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(pp, msk);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        MCL.SecretKey[] sk = new MCL.SecretKey[repeat_cnt];
        MCL.HashValue[] h = new MCL.HashValue[repeat_cnt];
        MCL.Randomness[] r = new MCL.Randomness[repeat_cnt];
        MCL.Randomness[] rp = new MCL.Randomness[repeat_cnt];
        MCL.Identity[] ID = new MCL.Identity[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            sk[i] = new MCL.SecretKey();
            ID[i] = pp.GenIdentity();
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL.HashValue();
            r[i] = new MCL.Randomness();
            rp[i] = new MCL.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(sk[i], pp, msk, ID[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, ID[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, ID[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], r[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, ID[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test ID_B_CollRes_XSL_2021")
    @ParameterizedTest(name = "test curve {0}, Identity len = {1}, swap_G1G2 true")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertIdentityLen")
    void MCLSwapTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|ID len:%d|swap:true: ", curve, n));
            System.out.printf("curve:%s (ID len: %d, swap: true): ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_swap scheme = new MCL_swap();
        MCL_swap.PublicParam pp = new MCL_swap.PublicParam(n);
        MCL_swap.MasterSecretKey msk = new MCL_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(pp, msk);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        MCL_swap.SecretKey[] sk = new MCL_swap.SecretKey[repeat_cnt];
        MCL_swap.HashValue[] h = new MCL_swap.HashValue[repeat_cnt];
        MCL_swap.Randomness[] r = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.Randomness[] rp = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.Identity[] ID = new MCL_swap.Identity[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            sk[i] = new MCL_swap.SecretKey();
            ID[i] = pp.GenIdentity();
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_swap.HashValue();
            r[i] = new MCL_swap.Randomness();
            rp[i] = new MCL_swap.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(sk[i], pp, msk, ID[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, ID[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, ID[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], r[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, ID[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @AfterEach
    void afterEach() {
        try {
            for (double x : time_cost) File_Writer.write(String.format("%.6f, ", x));
            File_Writer.write("\n");
            for (double x : time_cost) System.out.printf("%.6f, ", x);
            System.out.println();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterAll
    static void afterAll() {
        try {
            File_Writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
