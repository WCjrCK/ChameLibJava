package MCLTest.PBCHTest;

import MCLTest.BasicParam;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.PCH_DSS_2019.*;
import utils.BooleanFormulaParser;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class PCH_DSS_2019 extends BasicParam {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/PBCH/PCH_DSS_2019.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("PCH_DSS_2019\t\t\tSetUp, KeyGen, Hash, Check, Adapt\n");
            System.out.println("PCH_DSS_2019");
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test PCH_DSS_2019")
    @ParameterizedTest(name = "test curve {0} k = {1}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertk")
    void MCLTest(curve.MCL curve, int k) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|swap:false: ", curve, k));
            System.out.printf("curve:%s|k:%d|swap:false: ", curve, k);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL scheme = new MCL(k);
        MCL.PublicParam pp = new MCL.PublicParam();
        MCL.MasterPublicKey mpk = new MCL.MasterPublicKey();
        MCL.MasterSecretKey msk = new MCL.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(mpk, msk);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];

        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];


        MCL.SecretKey[] sk = new MCL.SecretKey[repeat_cnt];
        MCL.HashValue[] h = new MCL.HashValue[repeat_cnt];
        MCL.Randomness[] r = new MCL.Randomness[repeat_cnt];
        MCL.Randomness[] rp = new MCL.Randomness[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));

            sk[i] = new MCL.SecretKey();
            m[i] = UUID.randomUUID().toString();
            m2[i] = UUID.randomUUID().toString();
            h[i] = new MCL.HashValue();
            r[i] = new MCL.Randomness();
            rp[i] = new MCL.Randomness();
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

    @DisplayName("test PCH_DSS_2019")
    @ParameterizedTest(name = "test curve {0} k = {1}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertk")
    void MCLSwapTest(curve.MCL curve, int k) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|swap:true: ", curve, k));
            System.out.printf("curve:%s|k:%d|swap:true: ", curve, k);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_swap scheme = new MCL_swap(k);
        MCL_swap.PublicParam pp = new MCL_swap.PublicParam();
        MCL_swap.MasterPublicKey mpk = new MCL_swap.MasterPublicKey();
        MCL_swap.MasterSecretKey msk = new MCL_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(mpk, msk);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];

        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];


        MCL_swap.SecretKey[] sk = new MCL_swap.SecretKey[repeat_cnt];
        MCL_swap.HashValue[] h = new MCL_swap.HashValue[repeat_cnt];
        MCL_swap.Randomness[] r = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.Randomness[] rp = new MCL_swap.Randomness[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));

            sk[i] = new MCL_swap.SecretKey();
            m[i] = UUID.randomUUID().toString();
            m2[i] = UUID.randomUUID().toString();
            h[i] = new MCL_swap.HashValue();
            r[i] = new MCL_swap.Randomness();
            rp[i] = new MCL_swap.Randomness();
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
