package PerformTest.CH;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.BaseCH.Components.*;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.CH.CHName;
import ChameleonHash.CH.LabelCH.LabelCHFactory;
import ChameleonHash.Interface.BaseCH;
import ChameleonHash.Interface.CHET;
import ChameleonHash.Interface.LabelCH;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEName;
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
    static List<BufferedWriter> tscsgG1 = new ArrayList<>();
    static List<BufferedWriter> tscsgG2 = new ArrayList<>();
    static List<BufferedWriter> tscsgGT = new ArrayList<>();
    static HashMap<CHName, Integer> SNToIdx = new HashMap<>();

    static List<CHName> skipList = List.of(new CHName[]{
            CHName.CCT_2024,
            CHName.DKS_2020,
            CHName.LLA_2012,
            CHName.CZT_2011,
            CHName.CZK_2004,
            CHName.AM_2004,

//            CHName.BC_CDK_2017,
            CHName.KOG_CDK_2017,
            CHName.DSS_2020
    });

    static List<CurveName> runningCurve = List.of(new CurveName[]{
            CurveName.A,
            CurveName.A1,
            CurveName.E,
            CurveName.D_224,
            CurveName.BN254
    });

    public static Stream<Arguments> GetAllCHSchemeCurve() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> runningCurve.contains(b))
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllCHSchemeASCurve() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.ALL)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> runningCurve.contains(b))
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllCHSchemeSingleGroup() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> runningCurve.contains(b))
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(
                                        b -> EnumSet.allOf(CurveGroup.class).stream()
                                                .filter(c -> c != CurveGroup.Zp)
                                                .flatMap(c -> Stream.of(Arguments.of(a, b, c)))
                                )
                );
    }

    @BeforeAll
    static void initTest() {
        repeat_cnt = 100;
        for (CHName value : CHName.values()) new File(String.format("./data/CH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (CHName value : CHName.values()) {
                if (skipList.contains(value)) continue;
                BufferedWriter tmp;
                if (value.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP) {
                    tmp = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/real_time_cost_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tsc.add(tmp);
                } else tsc.add(null);
                if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC || value.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP) tscsgg.add(null);
                else {
                    tmp = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/real_time_cost_swapG1G2_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tscsgg.add(tmp);
                }
                if (value.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP) {
                    tmp = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/real_time_cost_inG1_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tscsgG1.add(tmp);
                    tmp = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/real_time_cost_inG2_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tscsgG2.add(tmp);
                    tmp = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/real_time_cost_inGT_%d.csv", value.name(), repeat_cnt)));
                    tmp.write("Curve, SetUp, KeyGen, Hash, Ver, Col\n");
                    tscsgGT.add(tmp);
                } else {
                    tscsgG1.add(null);
                    tscsgG2.add(null);
                    tscsgGT.add(null);
                }
                SNToIdx.put(value, i);
                i++;
            }
            System.out.println("\t\t\tSetUp, KeyGen, Hash, Ver, Col");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test CH real time cost")
    @Nested
    class CHRTCTest {
        private void testFunc(BufferedWriter real_time_test, CHConfig schemeConfig) throws IOException {
            System.out.println("Running " + schemeConfig.schemeName);
            if (schemeConfig.schemeName.has_label) testLabelCH(real_time_test, schemeConfig);
            else if (schemeConfig.schemeName.has_ET) testCHET(real_time_test, schemeConfig);
            else testBaseCH(real_time_test, schemeConfig);
        }

        private void testBaseCH(BufferedWriter real_time_test, CHConfig config) throws IOException {
            real_time_test.write(config.curveConfig.curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            BaseCH scheme = BaseCHFactory.createScheme(config);
            PublicParam pp = scheme.createPublicParam(config);

            int stage_id = -1;
            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Setup(pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            PublicKey[] pk = new PublicKey[repeat_cnt];
            SecretKey[] sk = new SecretKey[repeat_cnt];
            HashValue[] h = new HashValue[repeat_cnt];
            Randomness[] r = new Randomness[repeat_cnt];
            Randomness[] r_p = new Randomness[repeat_cnt];
            Message[] m = new Message[repeat_cnt];
            Message[] m_p = new Message[repeat_cnt];
            for (int i = 0; i < repeat_cnt; i++) {
                sk[i] = pp.createSecretKey();
                h[i] = pp.createHashValue();

                r[i] = pp.createRandomness();
                r_p[i] = pp.createRandomness();

                pk[i] = pp.createPublicKey();
                m[i] = pp.createMessage("msg_" + i);
                m_p[i] = pp.createMessage("msg_" + i + "_p");
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, pk[i], m[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Verify(pp, pk[i], m[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Collision(r_p[i], pp, pk[i], sk[i], m[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m_p[i], h[i], r_p[i]);
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
            real_time_test.flush();
        }

        private void testCHET(BufferedWriter real_time_test, CHConfig config) throws IOException {
            real_time_test.write(config.curveConfig.curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            CHET scheme = CHETFactory.createScheme(config);
            ChameleonHash.CH.CHET.Components.PublicParam pp = scheme.createPublicParam(config);

            int stage_id = -1;
            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Setup(pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            ChameleonHash.CH.CHET.Components.PublicKey[] pk = new ChameleonHash.CH.CHET.Components.PublicKey[repeat_cnt];
            ChameleonHash.CH.CHET.Components.SecretKey[] sk = new ChameleonHash.CH.CHET.Components.SecretKey[repeat_cnt];
            ChameleonHash.CH.CHET.Components.HashValue[] h = new ChameleonHash.CH.CHET.Components.HashValue[repeat_cnt];
            ChameleonHash.CH.CHET.Components.Randomness[] r = new ChameleonHash.CH.CHET.Components.Randomness[repeat_cnt];
            ChameleonHash.CH.CHET.Components.Randomness[] r_p = new ChameleonHash.CH.CHET.Components.Randomness[repeat_cnt];
            ChameleonHash.CH.CHET.Components.Message[] m = new ChameleonHash.CH.CHET.Components.Message[repeat_cnt];
            ChameleonHash.CH.CHET.Components.Message[] m_p = new ChameleonHash.CH.CHET.Components.Message[repeat_cnt];
            ChameleonHash.CH.CHET.Components.ETrapdoor[] etd = new ChameleonHash.CH.CHET.Components.ETrapdoor[repeat_cnt];
            for (int i = 0; i < repeat_cnt; i++) {
                sk[i] = pp.createSecretKey();
                h[i] = pp.createHashValue();

                r[i] = pp.createRandomness();
                r_p[i] = pp.createRandomness();

                pk[i] = pp.createPublicKey();
                m[i] = pp.createMessage("msg_" + i);
                m_p[i] = pp.createMessage("msg_" + i + "_p");
                etd[i] = pp.createETrapdoor();
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], etd[i], pp, pk[i], m[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Verify(pp, pk[i], m[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Collision(r_p[i], pp, pk[i], sk[i], m[i], etd[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m_p[i], h[i], r_p[i]);
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
            real_time_test.flush();
        }

        private void testLabelCH(BufferedWriter real_time_test, CHConfig config) throws IOException {
            real_time_test.write(config.curveConfig.curveName.name());
            double[] time_cost = {0, 0, 0, 0, 0};

            LabelCH scheme = LabelCHFactory.createScheme(config);
            ChameleonHash.CH.LabelCH.Components.PublicParam pp = scheme.createPublicParam(config);

            int stage_id = -1;
            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Setup(pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            ChameleonHash.CH.LabelCH.Components.PublicKey[] pk = new ChameleonHash.CH.LabelCH.Components.PublicKey[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.SecretKey[] sk = new ChameleonHash.CH.LabelCH.Components.SecretKey[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.HashValue[] h = new ChameleonHash.CH.LabelCH.Components.HashValue[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.Randomness[] r = new ChameleonHash.CH.LabelCH.Components.Randomness[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.Randomness[] r_p = new ChameleonHash.CH.LabelCH.Components.Randomness[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.Message[] m = new ChameleonHash.CH.LabelCH.Components.Message[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.Label[] l = new ChameleonHash.CH.LabelCH.Components.Label[repeat_cnt];
            ChameleonHash.CH.LabelCH.Components.Message[] m_p = new ChameleonHash.CH.LabelCH.Components.Message[repeat_cnt];
            for (int i = 0; i < repeat_cnt; i++) {
                sk[i] = pp.createSecretKey();
                h[i] = pp.createHashValue();

                r[i] = pp.createRandomness();
                r_p[i] = pp.createRandomness();

                pk[i] = pp.createPublicKey();
                m[i] = pp.createMessage("msg_" + i);
                m_p[i] = pp.createMessage("msg_" + i + "_p");

                l[i] = pp.createLabel("label_" + i);
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i], pp);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pp, pk[i], m[i], l[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m[i], l[i], h[i], r[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
                assertTrue(res, "Hash Check Failed");
            }

            for(int i = 0;i < repeat_cnt;++i) scheme.Verify(pp, pk[i], m[i], l[i], h[i], r[i]);

            {
                long start = System.nanoTime();
                for(int i = 0;i < repeat_cnt;++i) scheme.Collision(r_p[i], pp, pk[i], sk[i], m[i], l[i], h[i], r[i], m_p[i]);
                long end = System.nanoTime();
                double duration = (end - start) / 1.0e6;
                time_cost[++stage_id] = duration / repeat_cnt;
            }

            {
                boolean res = true;
                for(int i = 0;i < repeat_cnt;++i) res &= scheme.Verify(pp, pk[i], m_p[i], l[i], h[i], r_p[i]);
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
            real_time_test.flush();
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.CH.RealTimeTest#GetAllCHSchemeCurve")
        public void DSTest(CHName schemeName, CurveName curveName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", false);
            params.put("pke_config", new PKEConfig(PKEName.RSA));
            EllipticCurve.Curve.Config curveConfig = new EllipticCurve.Curve.Config(curveName, curve_param);
            CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
            params.put("ch_config", BC_CH);
            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
            System.out.print(curveName.name());
            if(tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.CH.RealTimeTest#GetAllCHSchemeASCurve")
        public void SGGTest(CHName schemeName, CurveName curveName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            params.put("pke_config", new PKEConfig(PKEName.RSA));
            EllipticCurve.Curve.Config curveConfig = new EllipticCurve.Curve.Config(curveName, curve_param);
            CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
            params.put("ch_config", BC_CH);
            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
            System.out.print(curveName + " swap G1G2");
            if(tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("test single group scheme")
        @ParameterizedTest(name = "test scheme {0} curve {1} group {2}")
        @MethodSource("PerformTest.CH.RealTimeTest#GetAllCHSchemeSingleGroup")
        void CHSingleGroupTest(CHName schemeName, CurveName curveName, CurveGroup curveGroup) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            params.put("curve_group", curveGroup);
            params.put("pke_config", new PKEConfig(PKEName.RSA));
            EllipticCurve.Curve.Config curveConfig = new EllipticCurve.Curve.Config(curveName, curve_param);
            CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
            params.put("ch_config", BC_CH);
            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
            switch (curveGroup) {
                case G1:
                    if(tscsgG1.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgG1.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
                case G2:
                    if(tscsgG2.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgG2.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
                case GT:
                    if(tscsgGT.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgGT.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
            }

        }
    }

    @AfterAll
    static void endTest() {
        try {
            for(int i = 0;i < tsc.size();++i) {
                tsc.get(i).close();
                if (tscsgg.get(i) != null) tscsgg.get(i).close();
                if (tscsgG1.get(i) != null) tscsgG1.get(i).close();
                if (tscsgG2.get(i) != null) tscsgG2.get(i).close();
                if (tscsgGT.get(i) != null) tscsgGT.get(i).close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
