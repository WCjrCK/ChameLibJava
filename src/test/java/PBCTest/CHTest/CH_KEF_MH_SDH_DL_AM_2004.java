package PBCTest.CHTest;

import PBCTest.BasicParam;
import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC;


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class CH_KEF_MH_SDH_DL_AM_2004 extends BasicParam {
    double[] time_cost = new double[4];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/CH/CH_KEF_MH_SDH_DL_AM_2004.txt"));
            File_Writer.write("CH_KEF_MH_SDH_DL_AM_2004\t\t\tKeyGen, Hash, Check, Adapt\n");
            System.out.println("CH_KEF_MH_SDH_DL_AM_2004");
            System.out.println("\t\t\tKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test CH_KEF_MH_SDH_DL_AM_2004")
    @ParameterizedTest(name = "test curve {0} group {1}")
    @MethodSource("PBCTest.BasicParam#GetPBCCartesianProduct")
    void PBCTest(curve.PBC curve, Group group) {
        try {
            File_Writer.write(String.format("%s.%s: ", curve, group));
            System.out.printf("%s.%s: ", curve, group);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PBC scheme = new PBC();
        PBC.PublicParam pp = new PBC.PublicParam(curve, group);

        PBC.PublicKey[] pk = new PBC.PublicKey[repeat_cnt];
        PBC.SecretKey[] sk = new PBC.SecretKey[repeat_cnt];
        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        Element[] m = new Element[repeat_cnt];
        Element[] m2 = new Element[repeat_cnt];
        Element[] L = new Element[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new PBC.PublicKey();
            sk[i] = new PBC.SecretKey();
            m[i] = pp.GP.GetZrElement();
            m2[i] = pp.GP.GetZrElement();
            L[i] = pp.GP.GetZrElement();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, pk[i], L[i], m[i]);
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, pk[i], sk[i], L[i], m[i], m2[i]);
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
