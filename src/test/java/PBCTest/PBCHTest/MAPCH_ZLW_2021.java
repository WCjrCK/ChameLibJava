package PBCTest.PBCHTest;

import PBCTest.BasicParam;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.PBCH.MAPCH_ZLW_2021.PBC;
import utils.BooleanFormulaParser;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class MAPCH_ZLW_2021 extends BasicParam {
    double[] time_cost = new double[6];

    @BeforeAll
    static void initTest() {
        InitialLib();
        System.out.println("MAPCH_ZLW_2021");
        System.out.println("\t\t\tSetUp, AuthSetUp, KeyGen, Hash, Check, Adapt");
    }

    @DisplayName("test MAPCH_ZLW_2021")
    @ParameterizedTest(name = "test curve {0} author number {1} lambda = {2}")
    @MethodSource("PBCTest.BasicParam#GetPBCSymmAuth")
    void PBCTest(curve.PBC curve, int auth_num, int lambda) {
        System.out.printf("%s (auth_num: %d, lambda: %d): ", curve, auth_num, lambda);
        PBC scheme = new PBC(lambda);
        PBC.PublicParam pp = new PBC.PublicParam(curve);

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.SetUp(pp);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        base.LSSS.PBC LSSS = new base.LSSS.PBC();
        base.LSSS.PBC.Matrix[] MSP = new base.LSSS.PBC.Matrix[repeat_cnt];
        BooleanFormulaParser.PolicyList[] pl = new BooleanFormulaParser.PolicyList[repeat_cnt];

        BooleanFormulaParser.AttributeList[] S = new BooleanFormulaParser.AttributeList[repeat_cnt];

        PBC.SecretKey SK = new PBC.SecretKey();
        PBC.HashValue[] h = new PBC.HashValue[repeat_cnt];
        PBC.Randomness[] r = new PBC.Randomness[repeat_cnt];
        PBC.Randomness[] rp = new PBC.Randomness[repeat_cnt];
        PBC.SecretKeyGroup[] SKG = new PBC.SecretKeyGroup[repeat_cnt];
        String[] GID = new String[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        PBC.Authority[] auths = new PBC.Authority[auth_num];
        for (int i = 0; i < auth_num; ++i) auths[i] = new PBC.Authority("auth_" + i, pp);

        HashMap<String, Integer> attr_auth_map = new HashMap<>();

        int auth_id = 0;
        for (int i = 0; i < repeat_cnt; i++) {
            MSP[i] = new base.LSSS.PBC.Matrix(pp.GP.Zr);
            pl[i] = new BooleanFormulaParser.PolicyList();
            S[i] = new BooleanFormulaParser.AttributeList();
            LSSS.GenLSSSMatrices(MSP[i], pl[i], RandomPolicyGenerator(S[i], true, 5));
            for (String attr : pl[i].policy) {
                auths[auth_id].MA_ABE_Auth.control_attr.add(attr);
                attr_auth_map.put(attr, auth_id);
                auth_id = (auth_id + 1) % auth_num;
            }
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.AuthSetup(auths[0]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        PBC.PublicKeyGroup PKG = new PBC.PublicKeyGroup(pp);
        for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i]);
        for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

        for (int i = 0; i < repeat_cnt; i++) {
            SKG[i] = new PBC.SecretKeyGroup();
            GID[i] = pp.GP.GetZrElement().toString();
            for (String attr : S[i].attrs) {
                auth_id = attr_auth_map.get(attr);
                scheme.KeyGen(auths[auth_id], SK, GID[i], attr);
                SKG[i].AddSK(SK);
            }

            m[i] = pp.GP.GetZrElement().toString();
            m2[i] = pp.GP.GetZrElement().toString();
            h[i] = new PBC.HashValue();
            r[i] = new PBC.Randomness();
            rp[i] = new PBC.Randomness();
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(auths[0], SK, GID[i], auths[0].MA_ABE_Auth.control_attr.get(0));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], PKG, MSP[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], PKG, m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], PKG, SKG[i], MSP[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], PKG, m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }
    }

    @AfterEach
    void afterEach() {
        for (double x : time_cost) System.out.printf("%.6f, ", x);
        System.out.println();
    }
}
