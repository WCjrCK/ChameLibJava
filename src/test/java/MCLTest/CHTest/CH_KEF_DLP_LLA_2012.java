package MCLTest.CHTest;

import MCLTest.BasicParam;
import com.herumi.mcl.Fr;
import curve.MCL;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import scheme.CH.CH_KEF_DLP_LLA_2012.*;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class CH_KEF_DLP_LLA_2012 extends BasicParam {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/CH/CH_KEF_DLP_LLA_2012.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("CH_KEF_DLP_LLA_2012\t\t\tKeyGen, Hash, Check, UForge, IForge\n");
            System.out.println("CH_KEF_DLP_LLA_2012");
            System.out.println("\t\t\tKeyGen, Hash, Check, UForge, IForge");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test G1")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(names = {"BN254", "BLS12_381"})
    void MCLG1Test(MCL curve) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G1: ", curve));
            System.out.printf("curve:%s|group:G1: ", curve);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G1 scheme = new MCL_G1();
        MCL_G1.PublicParam pp = new MCL_G1.PublicParam();
        MCL_G1.LabelManager LM = new MCL_G1.LabelManager(pp);

        MCL_G1.PublicKey[] pk = new MCL_G1.PublicKey[repeat_cnt];
        MCL_G1.SecretKey[] sk = new MCL_G1.SecretKey[repeat_cnt];
        MCL_G1.HashValue[] h = new MCL_G1.HashValue[repeat_cnt];
        MCL_G1.Label[] L = new MCL_G1.Label[repeat_cnt];
        MCL_G1.Randomness[] r = new MCL_G1.Randomness[repeat_cnt];
        MCL_G1.Randomness[] rp = new MCL_G1.Randomness[repeat_cnt];
        MCL_G1.Randomness[] rp2 = new MCL_G1.Randomness[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        Fr[] m3 = new Fr[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new MCL_G1.PublicKey();
            sk[i] = new MCL_G1.SecretKey();
            m[i] = new Fr();
            m2[i] = new Fr();
            m3[i] = new Fr();
            pp.GP.GetZrElement(m[i]);
            pp.GP.GetZrElement(m2[i]);
            pp.GP.GetZrElement(m3[i]);
            L[i] = new MCL_G1.Label();
            h[i] = new MCL_G1.HashValue();
            r[i] = new MCL_G1.Randomness();
            rp[i] = new MCL_G1.Randomness();
            rp2[i] = new MCL_G1.Randomness();
        }

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp, LM);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], L[i], pp, LM, pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, pk[i], L[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.UForge(rp[i], h[i], r[i], L[i], pp, pk[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.IForge(rp2[i], r[i], rp[i], m[i], m2[i], m3[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test G2")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(names = {"BN254", "BLS12_381"})
    void MCLG2Test(MCL curve) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G2: ", curve));
            System.out.printf("curve:%s|group:G2: ", curve);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G2 scheme = new MCL_G2();
        MCL_G2.PublicParam pp = new MCL_G2.PublicParam();
        MCL_G2.LabelManager LM = new MCL_G2.LabelManager(pp);

        MCL_G2.PublicKey[] pk = new MCL_G2.PublicKey[repeat_cnt];
        MCL_G2.SecretKey[] sk = new MCL_G2.SecretKey[repeat_cnt];
        MCL_G2.HashValue[] h = new MCL_G2.HashValue[repeat_cnt];
        MCL_G2.Label[] L = new MCL_G2.Label[repeat_cnt];
        MCL_G2.Randomness[] r = new MCL_G2.Randomness[repeat_cnt];
        MCL_G2.Randomness[] rp = new MCL_G2.Randomness[repeat_cnt];
        MCL_G2.Randomness[] rp2 = new MCL_G2.Randomness[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        Fr[] m3 = new Fr[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new MCL_G2.PublicKey();
            sk[i] = new MCL_G2.SecretKey();
            m[i] = new Fr();
            m2[i] = new Fr();
            m3[i] = new Fr();
            pp.GP.GetZrElement(m[i]);
            pp.GP.GetZrElement(m2[i]);
            pp.GP.GetZrElement(m3[i]);
            L[i] = new MCL_G2.Label();
            h[i] = new MCL_G2.HashValue();
            r[i] = new MCL_G2.Randomness();
            rp[i] = new MCL_G2.Randomness();
            rp2[i] = new MCL_G2.Randomness();
        }

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp, LM);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], L[i], pp, LM, pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, pk[i], L[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.UForge(rp[i], h[i], r[i], L[i], pp, pk[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.IForge(rp2[i], r[i], rp[i], m[i], m2[i], m3[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }


    @DisplayName("test GT")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(names = {"BN254", "BLS12_381"})
    void MCLGTTest(MCL curve) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:GT: ", curve));
            System.out.printf("curve:%s|group:GT: ", curve);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_GT scheme = new MCL_GT();
        MCL_GT.PublicParam pp = new MCL_GT.PublicParam();
        MCL_GT.LabelManager LM = new MCL_GT.LabelManager(pp);

        MCL_GT.PublicKey[] pk = new MCL_GT.PublicKey[repeat_cnt];
        MCL_GT.SecretKey[] sk = new MCL_GT.SecretKey[repeat_cnt];
        MCL_GT.HashValue[] h = new MCL_GT.HashValue[repeat_cnt];
        MCL_GT.Label[] L = new MCL_GT.Label[repeat_cnt];
        MCL_GT.Randomness[] r = new MCL_GT.Randomness[repeat_cnt];
        MCL_GT.Randomness[] rp = new MCL_GT.Randomness[repeat_cnt];
        MCL_GT.Randomness[] rp2 = new MCL_GT.Randomness[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        Fr[] m3 = new Fr[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new MCL_GT.PublicKey();
            sk[i] = new MCL_GT.SecretKey();
            m[i] = new Fr();
            m2[i] = new Fr();
            m3[i] = new Fr();
            pp.GP.GetZrElement(m[i]);
            pp.GP.GetZrElement(m2[i]);
            pp.GP.GetZrElement(m3[i]);
            L[i] = new MCL_GT.Label();
            h[i] = new MCL_GT.HashValue();
            r[i] = new MCL_GT.Randomness();
            rp[i] = new MCL_GT.Randomness();
            rp2[i] = new MCL_GT.Randomness();
        }

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp, LM);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], L[i], pp, LM, pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pp, pk[i], L[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.UForge(rp[i], h[i], r[i], L[i], pp, pk[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.IForge(rp2[i], r[i], rp[i], m[i], m2[i], m3[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pp, pk[i], L[i], m2[i]);
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
