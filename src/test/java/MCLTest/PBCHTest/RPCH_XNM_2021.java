package MCLTest.PBCHTest;

import MCLTest.BasicParam;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.RPCH_XNM_2021.*;
import utils.BooleanFormulaParser;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class RPCH_XNM_2021 extends BasicParam {
    double[] time_cost = new double[8];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/PBCH/RPCH_XNM_2021.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("RPCH_XNM_2021\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt\n");
            System.out.println("RPCH_XNM_2021");
            System.out.println("\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test RPCH_XNM_2021")
    @ParameterizedTest(name = "test curve {0} k = {1} leaf node = {2}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertkn")
    void MCLTest(curve.MCL curve, int k, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|n:%d|swap:false: ", curve, k, n));
            System.out.printf("curve:%s|k:%d|n:%d|swap:false: ", curve, k, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL scheme = new MCL(k);
        MCL.PublicParam pp = new MCL.PublicParam();
        MCL.MasterPublicKey MPK = new MCL.MasterPublicKey();
        MCL.MasterSecretKey MSK = new MCL.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
        base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        MCL.HashValue[] h = new MCL.HashValue[repeat_cnt];
        MCL.Randomness[] r = new MCL.Randomness[repeat_cnt];
        MCL.Randomness[] rp = new MCL.Randomness[repeat_cnt];
        MCL.SecretKey[] sk = new MCL.SecretKey[repeat_cnt];

        G1[] id = new G1[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        MCL.UpdateKey[] ku = new MCL.UpdateKey[repeat_cnt];
        MCL.DecryptKey[] dk = new MCL.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G1();
            Func.GetMCLG1RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            sk[i] = new MCL.SecretKey();
            ku[i] = new MCL.UpdateKey();
            dk[i] = new MCL.DecryptKey();
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
            m[i] = UUID.randomUUID().toString();
            m2[i] = UUID.randomUUID().toString();
            h[i] = new MCL.HashValue();
            r[i] = new MCL.Randomness();
            rp[i] = new MCL.Randomness();
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

    @DisplayName("test RPCH_XNM_2021")
    @ParameterizedTest(name = "test curve {0} k = {1} leaf node = {2}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertkn")
    void MCLSwapTest(curve.MCL curve, int k, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|k:%d|n:%d|swap:true: ", curve, k, n));
            System.out.printf("curve:%s|k:%d|n:%d|swap:true: ", curve, k, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_swap scheme = new MCL_swap(k);
        MCL_swap.PublicParam pp = new MCL_swap.PublicParam();
        MCL_swap.MasterPublicKey MPK = new MCL_swap.MasterPublicKey();
        MCL_swap.MasterSecretKey MSK = new MCL_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
        base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

        base.LSSS.MCL LSSS = new base.LSSS.MCL();
        base.LSSS.MCL.Matrix[] MSP = new base.LSSS.MCL.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        MCL_swap.HashValue[] h = new MCL_swap.HashValue[repeat_cnt];
        MCL_swap.Randomness[] r = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.Randomness[] rp = new MCL_swap.Randomness[repeat_cnt];
        MCL_swap.SecretKey[] sk = new MCL_swap.SecretKey[repeat_cnt];

        G2[] id = new G2[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        MCL_swap.UpdateKey[] ku = new MCL_swap.UpdateKey[repeat_cnt];
        MCL_swap.DecryptKey[] dk = new MCL_swap.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G2();
            Func.GetMCLG2RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            sk[i] = new MCL_swap.SecretKey();
            ku[i] = new MCL_swap.UpdateKey();
            dk[i] = new MCL_swap.DecryptKey();
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
            m[i] = UUID.randomUUID().toString();
            m2[i] = UUID.randomUUID().toString();
            h[i] = new MCL_swap.HashValue();
            r[i] = new MCL_swap.Randomness();
            rp[i] = new MCL_swap.Randomness();
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
