package PBCTest.PBCHTest;

import PBCTest.BasicParam;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.RPCH_XNM_2021.PBC;
import utils.BooleanFormulaParser;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class RPCH_XNM_2021 extends BasicParam {
    double[] time_cost = new double[8];

    @BeforeAll
    static void initTest() {
        InitialLib();
        repeat_cnt = Math.max(1, repeat_cnt / 4); // long time to run
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/PBCH/RPCH_XNM_2021.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("RPCH_XNM_2021\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt\n");
            System.out.println("RPCH_XNM_2021");
            System.out.println("\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test RPCH_XNM_2021")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2} leaf node = {3}")
    @MethodSource("PBCTest.BasicParam#GetPBCInvertkn")
    void PBCTest(curve.PBC curve, boolean swap_G1G2, int k, int n) {
        try {
            File_Writer.write(String.format("curve:%s|k:%d|n:%d|swap:%b: ", curve, k, n, swap_G1G2));
            System.out.printf("curve:%s|k:%d|n:%d|swap:%b: ", curve, k, n, swap_G1G2);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PBC scheme = new PBC(k);
        PBC.PublicParam pp = new PBC.PublicParam(curve, false);
        PBC.MasterPublicKey MPK = new PBC.MasterPublicKey();
        PBC.MasterSecretKey MSK = new PBC.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.BinaryTree.PBC BT = new base.BinaryTree.PBC(n);
        base.BinaryTree.PBC.RevokeList rl = new base.BinaryTree.PBC.RevokeList();

        base.LSSS.PBC LSSS = new base.LSSS.PBC();
        base.LSSS.PBC.Matrix[] MSP = new base.LSSS.PBC.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        PBC.SecretKey[] sk = new PBC.SecretKey[repeat_cnt];

        Element[] id = new Element[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        PBC.UpdateKey[] ku = new PBC.UpdateKey[repeat_cnt];
        PBC.DecryptKey[] dk = new PBC.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.PBC.Matrix(pp.GP.Zr);
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = pp.GP.GetZrElement();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            sk[i] = new PBC.SecretKey();
            ku[i] = new PBC.UpdateKey();
            dk[i] = new PBC.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(sk[i], BT, pp, MPK, MSK, S[i], id[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Revoke(rl, id[i], i + 1);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.UpdateKeyGen(ku[i], pp, MPK, BT, rl, i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.DecryptKeyGen(dk[i], pp, MPK, sk[i], ku[i], BT, rl);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }



        for (int i = 0; i < repeat_cnt; i++) {
            m[i] = pp.GP.GetZrElement().toString();
            m2[i] = pp.GP.GetZrElement().toString();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], MPK, m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pp, MPK, dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], MPK, m2[i]);
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
