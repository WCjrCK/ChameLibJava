package MCLTest.PBCHTest;

import MCLTest.BasicParam;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.RPCH_TMM_2022.*;
import utils.BooleanFormulaParser;
import utils.Func;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class RPCH_TMM_2022 extends BasicParam {
    double[] time_cost = new double[8];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/MCL/PBCH/RPCH_TMM_2022.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("RPCH_TMM_2022\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt\n");
            System.out.println("RPCH_TMM_2022");
            System.out.println("\t\t\tSetUp, KeyGen, Revoke, UpdateKeyGen, DecryptKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 false CH group = G1 leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLG1Test(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G1|n:%d|swap:false: ", curve, n));
            System.out.printf("curve:%s|group:G1|n:%d|swap:false: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G1 scheme = new MCL_G1();
        MCL_G1.PublicParam pp = new MCL_G1.PublicParam();
        MCL_G1.MasterPublicKey MPK = new MCL_G1.MasterPublicKey();
        MCL_G1.MasterSecretKey MSK = new MCL_G1.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_G1.HashValue[] h = new MCL_G1.HashValue[repeat_cnt];
        MCL_G1.Randomness[] r = new MCL_G1.Randomness[repeat_cnt];
        MCL_G1.Randomness[] rp = new MCL_G1.Randomness[repeat_cnt];
        MCL_G1.PublicKey[] pk = new MCL_G1.PublicKey[repeat_cnt];
        MCL_G1.SecretKey[] sk = new MCL_G1.SecretKey[repeat_cnt];

        G1[] id = new G1[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_G1.UpdateKey[] ku = new MCL_G1.UpdateKey[repeat_cnt];
        MCL_G1.DecryptKey[] dk = new MCL_G1.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G1();
            Func.GetMCLG1RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_G1.PublicKey();
            sk[i] = new MCL_G1.SecretKey();
            ku[i] = new MCL_G1.UpdateKey();
            dk[i] = new MCL_G1.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_G1.HashValue();
            r[i] = new MCL_G1.Randomness();
            rp[i] = new MCL_G1.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 true CH group = G1 leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLG1SwapTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G1|n:%d|swap:true: ", curve, n));
            System.out.printf("curve:%s|group:G1|n:%d|swap:true: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G1_swap scheme = new MCL_G1_swap();
        MCL_G1_swap.PublicParam pp = new MCL_G1_swap.PublicParam();
        MCL_G1_swap.MasterPublicKey MPK = new MCL_G1_swap.MasterPublicKey();
        MCL_G1_swap.MasterSecretKey MSK = new MCL_G1_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_G1_swap.HashValue[] h = new MCL_G1_swap.HashValue[repeat_cnt];
        MCL_G1_swap.Randomness[] r = new MCL_G1_swap.Randomness[repeat_cnt];
        MCL_G1_swap.Randomness[] rp = new MCL_G1_swap.Randomness[repeat_cnt];
        MCL_G1_swap.PublicKey[] pk = new MCL_G1_swap.PublicKey[repeat_cnt];
        MCL_G1_swap.SecretKey[] sk = new MCL_G1_swap.SecretKey[repeat_cnt];

        G2[] id = new G2[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_G1_swap.UpdateKey[] ku = new MCL_G1_swap.UpdateKey[repeat_cnt];
        MCL_G1_swap.DecryptKey[] dk = new MCL_G1_swap.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G2();
            Func.GetMCLG2RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_G1_swap.PublicKey();
            sk[i] = new MCL_G1_swap.SecretKey();
            ku[i] = new MCL_G1_swap.UpdateKey();
            dk[i] = new MCL_G1_swap.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_G1_swap.HashValue();
            r[i] = new MCL_G1_swap.Randomness();
            rp[i] = new MCL_G1_swap.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 false CH group = G2 leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLG2Test(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G2|n:%d|swap:false: ", curve, n));
            System.out.printf("curve:%s|group:G2|n:%d|swap:false: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G2 scheme = new MCL_G2();
        MCL_G2.PublicParam pp = new MCL_G2.PublicParam();
        MCL_G2.MasterPublicKey MPK = new MCL_G2.MasterPublicKey();
        MCL_G2.MasterSecretKey MSK = new MCL_G2.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_G2.HashValue[] h = new MCL_G2.HashValue[repeat_cnt];
        MCL_G2.Randomness[] r = new MCL_G2.Randomness[repeat_cnt];
        MCL_G2.Randomness[] rp = new MCL_G2.Randomness[repeat_cnt];
        MCL_G2.PublicKey[] pk = new MCL_G2.PublicKey[repeat_cnt];
        MCL_G2.SecretKey[] sk = new MCL_G2.SecretKey[repeat_cnt];

        G1[] id = new G1[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_G2.UpdateKey[] ku = new MCL_G2.UpdateKey[repeat_cnt];
        MCL_G2.DecryptKey[] dk = new MCL_G2.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G1();
            Func.GetMCLG1RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_G2.PublicKey();
            sk[i] = new MCL_G2.SecretKey();
            ku[i] = new MCL_G2.UpdateKey();
            dk[i] = new MCL_G2.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_G2.HashValue();
            r[i] = new MCL_G2.Randomness();
            rp[i] = new MCL_G2.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 true CH group = G2 leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLG2SwapTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:G2|n:%d|swap:true: ", curve, n));
            System.out.printf("curve:%s|group:G2|n:%d|swap:true: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_G2_swap scheme = new MCL_G2_swap();
        MCL_G2_swap.PublicParam pp = new MCL_G2_swap.PublicParam();
        MCL_G2_swap.MasterPublicKey MPK = new MCL_G2_swap.MasterPublicKey();
        MCL_G2_swap.MasterSecretKey MSK = new MCL_G2_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_G2_swap.HashValue[] h = new MCL_G2_swap.HashValue[repeat_cnt];
        MCL_G2_swap.Randomness[] r = new MCL_G2_swap.Randomness[repeat_cnt];
        MCL_G2_swap.Randomness[] rp = new MCL_G2_swap.Randomness[repeat_cnt];
        MCL_G2_swap.PublicKey[] pk = new MCL_G2_swap.PublicKey[repeat_cnt];
        MCL_G2_swap.SecretKey[] sk = new MCL_G2_swap.SecretKey[repeat_cnt];

        G2[] id = new G2[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_G2_swap.UpdateKey[] ku = new MCL_G2_swap.UpdateKey[repeat_cnt];
        MCL_G2_swap.DecryptKey[] dk = new MCL_G2_swap.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G2();
            Func.GetMCLG2RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_G2_swap.PublicKey();
            sk[i] = new MCL_G2_swap.SecretKey();
            ku[i] = new MCL_G2_swap.UpdateKey();
            dk[i] = new MCL_G2_swap.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_G2_swap.HashValue();
            r[i] = new MCL_G2_swap.Randomness();
            rp[i] = new MCL_G2_swap.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 false CH group = GT leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLGTTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:GT|n:%d|swap:false: ", curve, n));
            System.out.printf("curve:%s|group:GT|n:%d|swap:false: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_GT scheme = new MCL_GT();
        MCL_GT.PublicParam pp = new MCL_GT.PublicParam();
        MCL_GT.MasterPublicKey MPK = new MCL_GT.MasterPublicKey();
        MCL_GT.MasterSecretKey MSK = new MCL_GT.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_GT.HashValue[] h = new MCL_GT.HashValue[repeat_cnt];
        MCL_GT.Randomness[] r = new MCL_GT.Randomness[repeat_cnt];
        MCL_GT.Randomness[] rp = new MCL_GT.Randomness[repeat_cnt];
        MCL_GT.PublicKey[] pk = new MCL_GT.PublicKey[repeat_cnt];
        MCL_GT.SecretKey[] sk = new MCL_GT.SecretKey[repeat_cnt];

        G1[] id = new G1[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_GT.UpdateKey[] ku = new MCL_GT.UpdateKey[repeat_cnt];
        MCL_GT.DecryptKey[] dk = new MCL_GT.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G1();
            Func.GetMCLG1RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_GT.PublicKey();
            sk[i] = new MCL_GT.SecretKey();
            ku[i] = new MCL_GT.UpdateKey();
            dk[i] = new MCL_GT.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_GT.HashValue();
            r[i] = new MCL_GT.Randomness();
            rp[i] = new MCL_GT.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @DisplayName("test RPCH_TMM_2022")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 true CH group = GT leaf node = {3}")
    @MethodSource("MCLTest.BasicParam#GetMCLInvertGroupn")
    void MCLGTSwapTest(curve.MCL curve, int n) {
        Func.MCLInit(curve);
        try {
            File_Writer.write(String.format("curve:%s|group:GT|n:%d|swap:true: ", curve, n));
            System.out.printf("curve:%s|group:GT|n:%d|swap:true: ", curve, n);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        MCL_GT_swap scheme = new MCL_GT_swap();
        MCL_GT_swap.PublicParam pp = new MCL_GT_swap.PublicParam();
        MCL_GT_swap.MasterPublicKey MPK = new MCL_GT_swap.MasterPublicKey();
        MCL_GT_swap.MasterSecretKey MSK = new MCL_GT_swap.MasterSecretKey();

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(MPK, MSK, pp);
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

        MCL_GT_swap.HashValue[] h = new MCL_GT_swap.HashValue[repeat_cnt];
        MCL_GT_swap.Randomness[] r = new MCL_GT_swap.Randomness[repeat_cnt];
        MCL_GT_swap.Randomness[] rp = new MCL_GT_swap.Randomness[repeat_cnt];
        MCL_GT_swap.PublicKey[] pk = new MCL_GT_swap.PublicKey[repeat_cnt];
        MCL_GT_swap.SecretKey[] sk = new MCL_GT_swap.SecretKey[repeat_cnt];

        G2[] id = new G2[repeat_cnt];
        Fr[] m = new Fr[repeat_cnt];
        Fr[] m2 = new Fr[repeat_cnt];
        MCL_GT_swap.UpdateKey[] ku = new MCL_GT_swap.UpdateKey[repeat_cnt];
        MCL_GT_swap.DecryptKey[] dk = new MCL_GT_swap.DecryptKey[repeat_cnt];

        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.MCL.Matrix();
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            id[i] = new G2();
            Func.GetMCLG2RandomElement(id[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            pk[i] = new MCL_GT_swap.PublicKey();
            sk[i] = new MCL_GT_swap.SecretKey();
            ku[i] = new MCL_GT_swap.UpdateKey();
            dk[i] = new MCL_GT_swap.DecryptKey();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], BT, pp, MPK, MSK, S[i], id[i]);
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
            m[i] = new Fr();
            Func.GetMCLZrRandomElement(m[i]);
            m2[i] = new Fr();
            Func.GetMCLZrRandomElement(m2[i]);
            h[i] = new MCL_GT_swap.HashValue();
            r[i] = new MCL_GT_swap.Randomness();
            rp[i] = new MCL_GT_swap.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, MPK, pk[i], MSP[i], m[i], i);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], pk[i], dk[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
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
