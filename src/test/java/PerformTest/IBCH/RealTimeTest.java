package PerformTest.IBCH;

import EllipticCurve.Curve.CurveName;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.Components.*;
import scheme.IBCH.IBCH;
import scheme.SchemeCurveRequire;
import scheme.SchemeFactory;
import scheme.SchemeName;
import scheme.SchemeType;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static EllipticCurve.Curve.CurveName.PBC_CUSTOM;
import static EllipticCurve.Curve.CurveName.SECP256K1;
import static PerformTest.BasicParam.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RealTimeTest {
    static List<BufferedWriter> tsc = new ArrayList<>();
    static List<BufferedWriter> tscsgg = new ArrayList<>();
    static HashMap<SchemeName, Integer> SNToIdx = new HashMap<>();

    static List<SchemeName> skipList = List.of(new SchemeName[]{
//            IBCH_ZSS_2003_S1,
//            IBCH_ZSS_2003_S2,
    });

    @BeforeAll
    static void initTest() {
        repeat_cnt = 100;
        for (SchemeName value : SchemeName.values()) new File(String.format("./data/IBCH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (SchemeName value : SchemeName.values()) {
                if (value.schemeType == SchemeType.IBCH) {
                    BufferedWriter tmp = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/real_time_cost_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tsc.add(tmp);
                    if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                        tscsgg.add(null);
                    } else {
                        tmp = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/real_time_cost_swapG1G2_%d.csv", value.name(), repeat_cnt)));
                        tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                        tscsgg.add(tmp);
                    }
                    SNToIdx.put(value, i);
                    i++;
                }
            }
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Ver, Col");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test IBCH real time cost")
    @Nested
    class IBCHRTCTest {
        private void testFunc(BufferedWriter theo_storage_cost, SchemeName schemeName, CurveName curveName, Map<String, Object> params) throws IOException {
            theo_storage_cost.write(curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            IBCH scheme = (IBCH) SchemeFactory.createScheme(schemeName, curveName, params);
            PublicParam pp = scheme.createPublicParam(curveName, params);
            MasterSecretKey msk = scheme.createMasterSecretKey();

            int stage_id = -1;
            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Setup(pp, msk);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            SecretKey[] sk = new SecretKey[repeat_cnt];
            HashValue[] h = new HashValue[repeat_cnt];
            Randomness[] r = new Randomness[repeat_cnt];
            Randomness[] r_p = new Randomness[repeat_cnt];
            Identity[] ID = new Identity[repeat_cnt];
            Message[] m = new Message[repeat_cnt];
            Message[] m_p = new Message[repeat_cnt];
            for (int i = 0; i < repeat_cnt; i++) {
                sk[i] = scheme.createSecretKey();
                h[i] = scheme.createHashValue();

                r[i] = scheme.createRandomness();
                r_p[i] = scheme.createRandomness();

                ID[i] = pp.createIdentity("ID_" + i);
                m[i] = pp.createMessage("msg_" + i);
                m_p[i] = pp.createMessage("msg_" + i + "_p");
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
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Ver(pp, ID[i], m[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Ver(pp, ID[i], m[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Col(r_p[i], pp, ID[i], sk[i], m[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Ver(pp, ID[i], m_p[i], h[i], r_p[i]);
                assertTrue(res, "Adapt Check Failed");
            }
            try {
                for (double x : time_cost) theo_storage_cost.write(String.format(",%.6f", x));
                theo_storage_cost.write("\n");
                for (double x : time_cost) System.out.printf(",%.6f", x);
                System.out.println();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.BasicParam#GetSchemeCurveEnum")
        public void DSTest(SchemeName schemeName, CurveName curveName) throws IOException {
            if (skipList.contains(schemeName)) return;
            if (curveName == SECP256K1) {
                System.out.println("MCL 库未正确实现该曲线，跳过测试");
                return;
            }
            if (curveName == PBC_CUSTOM) {
                System.out.println("跳过自定义参数测试");
                return;
            }
            if (!schemeName.checkCurve(curveName)) {
                System.out.println("方案 " + schemeName.name() + " 不支持曲线 " + curveName + " ，跳过测试");
                return;
            }
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", false);
            params.put("curve_param", curve_param);
            System.out.print(curveName.name());
            if(tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeName, curveName, params);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.BasicParam#GetSchemeCurveEnum")
        public void SGGTest(SchemeName schemeName, CurveName curveName) throws IOException {
            if (skipList.contains(schemeName)) return;
            if (curveName == SECP256K1) {
                System.out.println("MCL 库未正确实现该曲线，跳过测试");
                return;
            }
            if (curveName == PBC_CUSTOM) {
                System.out.println("跳过自定义参数测试");
                return;
            }
            if (curveName.isSymmetic()) {
                System.out.println("对称群，无需交换G1 G2");
                return;
            }
            if (!schemeName.checkCurve(curveName)) {
                System.out.println("方案 " + schemeName.name() + " 不支持曲线 " + curveName + " ，跳过测试");
                return;
            }
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            params.put("curve_param", curve_param);
            System.out.print(curveName + " swap G1G2");
            if(tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeName, curveName, params);
        }
    }


    @AfterAll
    static void endTest() {
        try {
            for(int i = 0;i < tsc.size();++i) {
                tsc.get(i).close();
                if (tscsgg.get(i) != null) tscsgg.get(i).close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
