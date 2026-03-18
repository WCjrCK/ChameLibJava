package PerformTest.IBCH;

import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.BaseIBCH.Components.*;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.IBCH.IBCHName;
import ChameleonHash.IBCH.LabelIBCH.LabelIBCHFactory;
import ChameleonHash.Interface.BaseIBCH;
import ChameleonHash.Interface.LabelIBCH;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveName;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.PBC_CUSTOM;
import static EllipticCurve.Curve.CurveName.SECP256K1;
import static PerformTest.BasicParam.repeat_cnt;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RealTimeTest {
    static List<BufferedWriter> tsc = new ArrayList<>();
    static List<BufferedWriter> tscsgg = new ArrayList<>();
    static HashMap<IBCHName, Integer> SNToIdx = new HashMap<>();

    static List<IBCHName> skipList = List.of(new IBCHName[]{
            IBCHName.ZSS_2003_S1,
            IBCHName.ZSS_2003_S2,
            IBCHName.CZS_2014,
            IBCHName.LSX_2022,
            IBCHName.XSL_2021,
            IBCHName.LJF_2025,
    });

    public static Stream<Arguments> GetAllIBCHSchemeCurve() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> ((b != SECP256K1) && (b != PBC_CUSTOM)))
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllIBCHSchemeASCurve() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> ((b != SECP256K1) && (b != PBC_CUSTOM)))
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }


    @BeforeAll
    static void initTest() {
        repeat_cnt = 1000;
        for (IBCHName value : IBCHName.values()) new File(String.format("./data/IBCH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (IBCHName value : IBCHName.values()) {
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
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Ver, Col");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test IBCH real time cost")
    @Nested
    class IBCHRTCTest {
        private void testFunc(BufferedWriter real_time_test, IBCHConfig schemeConfig) throws IOException {
            if (schemeConfig.schemeName.has_label) testLabelIBCH(real_time_test, schemeConfig);
            else testBaseIBCH(real_time_test, schemeConfig);
        }

        private void testBaseIBCH(BufferedWriter real_time_test, IBCHConfig config) throws IOException {
            real_time_test.write(config.curveConfig.curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            BaseIBCH scheme = BaseIBCHFactory.createScheme(config);
            PublicParam pp = scheme.createPublicParam(config);
            MasterSecretKey msk = pp.createMasterSecretKey();

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
                sk[i] = pp.createSecretKey();
                h[i] = pp.createHashValue();

                r[i] = pp.createRandomness();
                r_p[i] = pp.createRandomness();

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
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, ID[i], m[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Verify(pp, ID[i], m[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Collision(r_p[i], pp, ID[i], sk[i], m[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, ID[i], m_p[i], h[i], r_p[i]);
                assertTrue(res, "Adapt Check Failed");
            }
            try {
                for (double x : time_cost) real_time_test.write(String.format(",%.6f", x));
                real_time_test.write("\n");
                for (double x : time_cost) System.out.printf(",%.6f", x);
                System.out.println();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private void testLabelIBCH(BufferedWriter real_time_test, IBCHConfig config) throws IOException {
            real_time_test.write(config.curveConfig.curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            LabelIBCH scheme = LabelIBCHFactory.createScheme(config);
            ChameleonHash.IBCH.LabelIBCH.Components.PublicParam pp = scheme.createPublicParam(config);
            ChameleonHash.IBCH.LabelIBCH.Components.MasterSecretKey msk = pp.createMasterSecretKey();

            int stage_id = -1;
            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Setup(pp, msk);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            ChameleonHash.IBCH.LabelIBCH.Components.SecretKey[] sk = new ChameleonHash.IBCH.LabelIBCH.Components.SecretKey[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.HashValue[] h = new ChameleonHash.IBCH.LabelIBCH.Components.HashValue[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Randomness[] r = new ChameleonHash.IBCH.LabelIBCH.Components.Randomness[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Randomness[] r_p = new ChameleonHash.IBCH.LabelIBCH.Components.Randomness[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Identity[] ID = new ChameleonHash.IBCH.LabelIBCH.Components.Identity[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Message[] m = new ChameleonHash.IBCH.LabelIBCH.Components.Message[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Label[] l = new ChameleonHash.IBCH.LabelIBCH.Components.Label[repeat_cnt];
            ChameleonHash.IBCH.LabelIBCH.Components.Message[] m_p = new ChameleonHash.IBCH.LabelIBCH.Components.Message[repeat_cnt];
            for (int i = 0; i < repeat_cnt; i++) {
                sk[i] = pp.createSecretKey();
                h[i] = pp.createHashValue();

                r[i] = pp.createRandomness();
                r_p[i] = pp.createRandomness();

                ID[i] = pp.createIdentity("ID_" + i);
                m[i] = pp.createMessage("msg_" + i);
                m_p[i] = pp.createMessage("msg_" + i + "_p");

                l[i] = pp.createLabel("label_" + i);
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
                for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, ID[i], m[i], l[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, ID[i], m[i], l[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Verify(pp, ID[i], m[i], l[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Collision(r_p[i], pp, ID[i], sk[i], m[i], l[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, ID[i], m_p[i], l[i], h[i], r_p[i]);
                assertTrue(res, "Adapt Check Failed");
            }
            try {
                for (double x : time_cost) real_time_test.write(String.format(",%.6f", x));
                real_time_test.write("\n");
                for (double x : time_cost) System.out.printf(",%.6f", x);
                System.out.println();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.IBCH.RealTimeTest#GetAllIBCHSchemeCurve")
        public void DSTest(IBCHName schemeName, CurveName curveName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 64);
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", false);
            EllipticCurve.Curve.Config curveConfig = new EllipticCurve.Curve.Config(curveName, curve_param);
            IBCHConfig schemeConfig = new IBCHConfig(schemeName, curveConfig, params);
            System.out.print(curveName.name());
            if(tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.IBCH.RealTimeTest#GetAllIBCHSchemeASCurve")
        public void SGGTest(IBCHName schemeName, CurveName curveName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 64);
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            EllipticCurve.Curve.Config curveConfig = new EllipticCurve.Curve.Config(curveName, curve_param);
            IBCHConfig schemeConfig = new IBCHConfig(schemeName, curveConfig, params);
            System.out.print(curveName + " swap G1G2");
            if(tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig);
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
