package MCLTest.PBCHTest;

import MCLTest.BasicParam;
import com.herumi.mcl.Fr;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.PCHBA_TLL_2020.*;
import utils.BooleanFormulaParser;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class PCHBA_TLL_2020 extends BasicParam {
    double[] time_cost = new double[6];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/PBCH/PCHBA_TLL_2020.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("PCHBA_TLL_2020\t\t\tSetUp, AssignUser, KeyGen, Hash, Check, Adapt\n");
            System.out.println("PCHBA_TLL_2020");
            System.out.println("\t\t\tSetUp, AssignUser, KeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test PCHBA_TLL_2020")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 false k = {1}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertIdentityLen")
    void MCLTest(curve.MCL curve, int k) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|swap:false: ", curve, k));
            System.out.printf("curve:%s|k:%d|swap:false: ", curve, k);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL scheme = new MCL();
        MCL.PublicParam pp = new MCL.PublicParam();
        MCL.MasterPublicKey MPK = new MCL.MasterPublicKey();
        MCL.MasterSecretKey MSK = new MCL.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, k);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        MCL.HashValue[] h = new MCL.HashValue[repeat_cnt];
        MCL.Randomness[] r = new MCL.Randomness[repeat_cnt];
        MCL.Randomness[] rp = new MCL.Randomness[repeat_cnt];
        MCL.User[] u1 = new MCL.User[repeat_cnt];
        MCL.User[] u2 = new MCL.User[repeat_cnt];

        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            u1[i] = new MCL.User(k / 3);
            scheme.AssignUser(u1[i], MPK, MSK);
            scheme.KeyGen(u1[i], pp, MPK, MSK, S[i]);
            u2[i] = new MCL.User(u1[i],  k / 2);
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.AssignUser(u2[i], MPK, MSK);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(u2[i], pp, MPK, MSK, S[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        for (int i = 0; i < repeat_cnt; i++) {
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, u2[i], MSP[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, MPK, m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, MPK, MSK, u1[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, MPK, m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test PCHBA_TLL_2020")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 true k = {1}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertIdentityLen")
    void MCLSwapTest(curve.MCL curve, int k) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|swap:true: ", curve, k));
            System.out.printf("curve:%s|k:%d|swap:true: ", curve, k);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_swap scheme = new MCL_swap();
        MCL_swap.PublicParam pp = new MCL_swap.PublicParam();
        MCL_swap.MasterPublicKey MPK = new MCL_swap.MasterPublicKey();
        MCL_swap.MasterSecretKey MSK = new MCL_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, k);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        MCL_swap.HashValue[] h = new MCL_swap.HashValue[repeat_cnt];
        MCL_swap.Randomness[] r = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.Randomness[] rp = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.User[] u1 = new MCL_swap.User[repeat_cnt];
        MCL_swap.User[] u2 = new MCL_swap.User[repeat_cnt];

        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            u1[i] = new MCL_swap.User(k / 3);
            scheme.AssignUser(u1[i], MPK, MSK);
            scheme.KeyGen(u1[i], pp, MPK, MSK, S[i]);
            u2[i] = new MCL_swap.User(u1[i],  k / 2);
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.AssignUser(u2[i], MPK, MSK);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(u2[i], pp, MPK, MSK, S[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        for (int i = 0; i < repeat_cnt; i++) {
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, u2[i], MSP[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, MPK, m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, MPK, MSK, u1[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, MPK, m2[i]);
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
