package PBCTest.PBCHTest;

import PBCTest.BasicParam;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.DPCH_MXN_2022.PBC;
import utils.BooleanFormulaParser;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class DPCH_MXN_2022 extends BasicParam {
    double[] time_cost = new double[7];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/PBCH/DPCH_MXN_2022.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("DPCH_MXN_2022\t\t\tSetUp, ModSetUp, AuthSetUp, ModKeyGen, Hash, Check, Adapt\n");
            System.out.println("DPCH_MXN_2022");
            System.out.println("\t\t\tSetUp, ModSetUp, AuthSetUp, ModKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test DPCH_MXN_2022")
    @ParameterizedTest(name = "test curve {0} author number {1} lambda = {2}")
    @MethodSource("PBCTest.BasicParam#GetPBCSymmAuthBigLambda")
    void PBCTest(curve.PBC curve, int auth_num, int lambda) {
        try {
            File_Writer.write(String.format("curve:%s|auth_num:%d|lambda:%d: ", curve, auth_num, lambda));
            System.out.printf("curve:%s|auth_num:%d|lambda:%d: ", curve, auth_num, lambda);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PBC scheme = new PBC(lambda);
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

        base.LSSS.PBC LSSS = new base.LSSS.PBC();
        base.LSSS.PBC.Matrix[] MSP = new base.LSSS.PBC.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];
        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        PBC.Modifier[] mod1 = new PBC.Modifier[repeat_cnt];

        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        PBC.SecretKeyGroup[] SKG = new PBC.SecretKeyGroup[repeat_cnt];
        String[] GID = new String[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        PBC.Authority[] auths = new PBC.Authority[auth_num];
        for (int i = 0; i < auth_num; ++i) auths[i] = new PBC.Authority("auth_" + i);

        HashMap<String, Integer> attr_auth_map = new HashMap<>();

        int auth_id = 0;
        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.PBC.Matrix(pp.GP_MA_ABE.GP.Zr);
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            GID[i] = pp.GP_MA_ABE.GP.GetZrElement().toString();
            mod1[i] = new PBC.Modifier(GID[i]);
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            for (String attr : pl[i].policy) {
                auths[auth_id].MA_ABE_Auth.control_attr.add(attr);
                attr_auth_map.put(attr, auth_id);
                auth_id = (auth_id + 1) % auth_num;
            }
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.ModSetup(mod1[i], pp, MSK);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.AuthSetup(auths[0], pp);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        PBC.PublicKeyGroup PKG = new PBC.PublicKeyGroup();
        for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i], pp);
        for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.ModKeyGen(mod1[i], pp, MPK, auths[0], auths[0].MA_ABE_Auth.control_attr.get(0));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        for (int i = 0; i < repeat_cnt; i++) {
            SKG[i] = new PBC.SecretKeyGroup();
            for (String attr : S[i].attrs) {
                auth_id = attr_auth_map.get(attr);
                scheme.ModKeyGen(mod1[i], pp, MPK, auths[auth_id], attr);
                SKG[i].AddSK(mod1[i]);
            }

            m[i] = pp.GP_MA_ABE.GP.GetZrElement().toString();
            m2[i] = pp.GP_MA_ABE.GP.GetZrElement().toString();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], PKG, MSP[i], pp, MPK, m[i]);
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], PKG, SKG[i], MSP[i], pp, MPK, MSK, m[i], m2[i]);
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
