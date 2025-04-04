package PBCTest.PBCHTest;

import PBCTest.BasicParam;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.PCHBA_TLL_2020.PBC;
import utils.BooleanFormulaParser;

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
        repeat_cnt = Math.max(1, repeat_cnt / 10); // long time to run
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/PBCH/PCHBA_TLL_2020.txt"));
            File_Writer.write("PCHBA_TLL_2020\t\t\tSetUp, AssignUser, KeyGen, Hash, Check, Adapt\n");
            System.out.println("PCHBA_TLL_2020");
            System.out.println("\t\t\tSetUp, AssignUser, KeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test PCHBA_TLL_2020")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2}")
    @MethodSource("PBCTest.BasicParam#GetPBCInvertk")
    void PBCTest(curve.PBC curve, boolean swap_G1G2, int k) {
        try {
            File_Writer.write(String.format("curve:%s|k:%d|swap:%b: ", curve, k, swap_G1G2));
            System.out.printf("curve:%s|k:%d|swap:%b: ", curve, k, swap_G1G2);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PBC scheme = new PBC();
        PBC.PublicParam pp = new PBC.PublicParam(curve, false);
        PBC.MasterPublicKey MPK = new PBC.MasterPublicKey();
        PBC.MasterSecretKey MSK = new PBC.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp, k);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.PBC LSSS = new base.LSSS.PBC();
        base.LSSS.PBC.Matrix[] MSP = new base.LSSS.PBC.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        PBC.User[] u1 = new PBC.User[repeat_cnt];
        PBC.User[] u2 = new PBC.User[repeat_cnt];

        Element[] m = new Element[repeat_cnt];
        Element[] m2 = new Element[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.PBC.Matrix(pp.GP.Zr);
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            u1[i] = new PBC.User(pp, k / 2);
            u2[i] = new PBC.User(u1[i], pp, k);
            scheme.AssignUser(u1[i], MPK, MSK);
            scheme.KeyGen(u1[i], pp, MPK, MSK, S[i]);
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
            m[i] = pp.GP.GetZrElement();
            m2[i] = pp.GP.GetZrElement();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, MPK, MSK, u2[i], MSP[i], m[i], m2[i]);
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
