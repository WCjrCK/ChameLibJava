package PBCTest.IBCHTest;

import PBCTest.BasicParam;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.IBCH.IB_CH_ZSS_S1_2003.PBC;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class IB_CH_ZSS_S1_2003 extends BasicParam {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/IBCH/IB_CH_ZSS_S1_2003.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("IB_CH_ZSS_S1_2003\t\t\tSetUp, KeyGen, Hash, Check, Adapt\n");
            System.out.println("IB_CH_ZSS_S1_2003");
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test IB_CH_ZSS_S1_2003")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
    @MethodSource("PBCTest.BasicParam#GetPBCInvert")
    void PBCTest(curve.PBC curve, boolean swap_G1G2) {
        try {
            File_Writer.write(String.format("curve:%s|swap:%b: ", curve, swap_G1G2));
            System.out.printf("curve:%s|swap:%b: ", curve, swap_G1G2);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PBC scheme = new PBC();
        PBC.PublicParam pp = new PBC.PublicParam(curve, swap_G1G2);
        PBC.MasterSecretKey msk = new PBC.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(pp, msk);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        PBC.SecretKey[] sk = new PBC.SecretKey[repeat_cnt];
        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        Element[] ID = new Element[repeat_cnt];
        Element[] m = new Element[repeat_cnt];
        Element[] m2 = new Element[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            sk[i] = new PBC.SecretKey();
            ID[i] = pp.GP.GetZrElement();
            m[i] = pp.GP.GetZrElement();
            m2[i] = pp.GP.GetZrElement();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], r[i], pp, sk[i], m[i], m2[i]);
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
