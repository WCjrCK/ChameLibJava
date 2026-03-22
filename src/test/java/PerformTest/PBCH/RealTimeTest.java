package PerformTest.PBCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.BAPBCH.BAPBCHFactory;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.ABE.utils.BooleanFormulaParser;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
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
    static List<List<BufferedWriter>> tscnm = new ArrayList<>();
    static List<List<BufferedWriter>> tscnmsgg = new ArrayList<>();
    static HashMap<PBCHName, Integer> SNToIdx = new HashMap<>();

    static List<PBCHName> skipList = List.of(
            PBCHName.XNM_2021
    );

    static List<CurveName> runningCurve = List.of(
            CurveName.A,
            CurveName.A1,
            CurveName.E,
            CurveName.D_224,
            CurveName.BN254
    );

    static List<int[]> matrixSizeList = List.of(
//            new int[]{64, 10},
            new int[]{64, 20} // ,
//            new int[]{64, 30},
//            new int[]{64, 40},
//            new int[]{64, 50},
//            new int[]{10, 5},
//            new int[]{20, 5},
//            new int[]{30, 5},
//            new int[]{40, 5},
//            new int[]{50, 5}
    );

    public static Stream<Arguments> GetAllPBCHSchemeCurve() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllPBCHSchemeASCurve() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllPBCHSchemeCurveMatrixNM() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> matrixSizeList.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c[0], c[1]))))
                );
    }

    public static Stream<Arguments> GetAllPBCHSchemeASCurveMatrixNM() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> matrixSizeList.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c[0], c[1]))))
                );
    }

    @BeforeAll
    static void initTest() {
        repeat_cnt = 10;
        for (PBCHName value : PBCHName.values()) new File(String.format("./data/PBCH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (PBCHName value : PBCHName.values()) {
                if (skipList.contains(value)) continue;
                tsc.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_%d.csv", value.name(), repeat_cnt), value));
                if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                    tscsgg.add(null);
                } else {
                    tscsgg.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_swapG1G2_%d.csv", value.name(), repeat_cnt), value));
                }

                List<BufferedWriter> nmWriter = new ArrayList<>();
                List<BufferedWriter> nmSwapWriter = new ArrayList<>();
                for (int[] size : matrixSizeList) {
                    nmWriter.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_n_%d_m_%d_%d.csv", value.name(), size[0], size[1], repeat_cnt), value));
                    if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                        nmSwapWriter.add(null);
                    } else {
                        nmSwapWriter.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_n_%d_m_%d_swapG1G2_%d.csv", value.name(), size[0], size[1], repeat_cnt), value));
                    }
                }
                tscnm.add(nmWriter);
                tscnmsgg.add(nmSwapWriter);

                SNToIdx.put(value, i);
                ++i;
            }
            System.out.println("\t\t\tSetUp, KeyGen/Assign, Hash, Ver, Col");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static BufferedWriter createWriter(String path, PBCHName schemeName) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(path));
        writer.write(getCsvHeader(schemeName));
        return writer;
    }

    private static String getCsvHeader(PBCHName schemeName) {
        if (schemeName.has_blackbox_accountability) return "Curve, SetUp, AssignUser, KeyGen, Hash, Ver, Col\n";
        return "Curve, SetUp, KeyGen, Hash, Ver, Col\n";
    }

    private static PBCHConfig buildConfig(PBCHName schemeName, CurveName curveName, boolean swapG1G2) {
        Map<String, Object> curveParam = new HashMap<>();
        curveParam.put("swap_G1G2", swapG1G2);
        Config curveConfig = new Config(curveName, curveParam);

        Map<String, Object> params = new HashMap<>();
        Map<String, Object> chetParam = new HashMap<>();
        Map<String, Object> chParam = new HashMap<>();
        chParam.put("curve_group", CurveGroup.G1);
        chetParam.put("ch_config", new CHConfig(CHName.DSS_2020, curveConfig, chParam));
        params.put("chet_config", new CHConfig(CHName.BC_CDK_2017, curveConfig, chetParam));

        Map<String, Object> seParam = new HashMap<>();
        seParam.put("algorithm", "AES");
        seParam.put("transformation", "AES/ECB/PKCS5Padding");
        params.put("se_config", new SEConfig(SEName.AES, seParam));

        params.put("id_len", 32);
        params.put("max_user", 2048);
        return new PBCHConfig(schemeName, curveConfig, params);
    }

    private static PolicyCase defaultPolicyCase() {
        return new PolicyCase("A&(DDDD|(BB&CCC))", new HashSet<>(Set.of("A", "DDDD")));
    }

    private static PolicyCase matrixPolicyCase(int n, int m) {
        BooleanFormulaParser.GeneratedFormula generated = BooleanFormulaParser.generateSatisfiableFormula(n, m);
        return new PolicyCase(generated.formula, new HashSet<>(generated.satisfyingAttributes.attrs));
    }

    private static int matrixIndex(int n, int m) {
        for (int i = 0; i < matrixSizeList.size(); ++i) {
            if (matrixSizeList.get(i)[0] == n && matrixSizeList.get(i)[1] == m) return i;
        }
        throw new IllegalArgumentException(String.format("unsupported matrix size n=%d, m=%d", n, m));
    }

    private static void addAttrs(Attributes attrs, Set<String> satisfyingAttrs) {
        for (String attr : satisfyingAttrs) attrs.addAttr(attr);
    }

    private static void writeTimeCost(BufferedWriter realTimeTest, double[] timeCost) throws IOException {
        for (double x : timeCost) realTimeTest.write(String.format(",%.6f", x));
        realTimeTest.write("\n");
        for (double x : timeCost) System.out.printf(",%.6f", x);
        System.out.println();
        realTimeTest.flush();
    }

    private void testFunc(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCase policyCase) throws IOException {
        System.out.println("Running " + schemeConfig.schemeName);
        if (schemeConfig.schemeName.has_blackbox_accountability) testBAPBCH(realTimeTest, schemeConfig, policyCase);
        else if (schemeConfig.schemeName.revocable) {
            throw new UnsupportedOperationException("Revocable PBCH real-time test is not enabled yet");
        } else testBasePBCH(realTimeTest, schemeConfig, policyCase);
    }

    private void testBasePBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCase policyCase) throws IOException {
        realTimeTest.write(schemeConfig.curveConfig.curveName.name());
        double[] timeCost = {0, 0, 0, 0, 0};

        BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();

        int stageId = -1;
        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Setup(pp, mpk, msk);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        Policy P = pp.createPolicy(policyCase.formula);
        Attributes[] attrs = new Attributes[repeat_cnt];
        SecretKey[] sk = new SecretKey[repeat_cnt];
        HashValue[] h = new HashValue[repeat_cnt];
        Randomness[] r = new Randomness[repeat_cnt];
        Randomness[] r_p = new Randomness[repeat_cnt];
        Message[] m = new Message[repeat_cnt];
        Message[] m_p = new Message[repeat_cnt];
        for (int i = 0; i < repeat_cnt; ++i) {
            attrs[i] = pp.createAttributes();
            addAttrs(attrs[i], policyCase.satisfyingAttrs);
            sk[i] = pp.createSecretKey();
            h[i] = pp.createHashValue();
            r[i] = pp.createRandomness();
            r_p[i] = pp.createRandomness();
            m[i] = pp.createMessage("msg_" + i);
            m_p[i] = pp.createMessage("msg_" + i + "_p");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.KeyGen(sk[i], pp, mpk, msk, attrs[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Hash(h[i], r[i], pp, mpk, m[i], P);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m[i], h[i], r[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Collision(r_p[i], pp, mpk, sk[i], m[i], h[i], r[i], m_p[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            boolean res = true;
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m_p[i], h[i], r_p[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        writeTimeCost(realTimeTest, timeCost);
    }

    private void testBAPBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCase policyCase) throws IOException {
        realTimeTest.write(schemeConfig.curveConfig.curveName.name());
        double[] timeCost = {0, 0, 0, 0, 0, 0};

        BAPBCH scheme = BAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.BAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();

        int stageId = -1;
        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Setup(pp, mpk, msk);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        Policy P = pp.createPolicy(policyCase.formula);
        User[] users = new User[repeat_cnt];
        HashValue[] h = new HashValue[repeat_cnt];
        Randomness[] r = new Randomness[repeat_cnt];
        Randomness[] r_p = new Randomness[repeat_cnt];
        Message[] m = new Message[repeat_cnt];
        Message[] m_p = new Message[repeat_cnt];
        int userIdLen = Math.max(1, ((int) schemeConfig.params.get("id_len")) / 3);
        for (int i = 0; i < repeat_cnt; ++i) {
            users[i] = pp.createUser(userIdLen);
            h[i] = pp.createHashValue();
            r[i] = pp.createRandomness();
            r_p[i] = pp.createRandomness();
            m[i] = pp.createMessage("msg_" + i);
            m_p[i] = pp.createMessage("msg_" + i + "_p");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.AssignUser(users[i], pp, mpk, msk);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        for (int i = 0; i < repeat_cnt; ++i) addAttrs(users[i].S, policyCase.satisfyingAttrs);

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.KeyGen(users[i], pp, mpk, msk);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Hash(h[i], r[i], pp, mpk, users[i], m[i], P);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m[i], h[i], r[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Collision(r_p[i], pp, mpk, msk, users[i], m[i], P, h[i], r[i], m_p[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = (end - start) / 1.0e6 / repeat_cnt;
        }

        {
            boolean res = true;
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m_p[i], h[i], r_p[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        writeTimeCost(realTimeTest, timeCost);
    }

//    @DisplayName("test PBCH real time cost")
//    @Nested
//    class PBCHRTCTest {
//        @DisplayName("test direct scheme")
//        @ParameterizedTest(name = "test scheme {0} in curve {1}")
//        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeCurve")
//        public void DSTest(PBCHName schemeName, CurveName curveName) throws IOException {
//            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false);
//            System.out.print(curveName.name());
//            if (tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig, defaultPolicyCase());
//        }
//
//        @DisplayName("swap G1 and G2")
//        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
//        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeASCurve")
//        public void SGGTest(PBCHName schemeName, CurveName curveName) throws IOException {
//            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true);
//            System.out.print(curveName + " swap G1G2");
//            if (tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig, defaultPolicyCase());
//        }
//    }

    @DisplayName("test PBCH real time cost diff matrix size")
    @Nested
    class PBCHRTCMatTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with n {2} m {3}")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeCurveMatrixNM")
        public void DSTest(PBCHName schemeName, CurveName curveName, int n, int m) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false);
            System.out.print(curveName.name() + " n=" + n + " m=" + m);
            int matrixIdx = matrixIndex(n, m);
            if (tscnm.get(SNToIdx.get(schemeName)).get(matrixIdx) != null) {
                testFunc(tscnm.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, matrixPolicyCase(n, m));
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with n {2} m {3} and swap G1 G2")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeASCurveMatrixNM")
        public void SGGTest(PBCHName schemeName, CurveName curveName, int n, int m) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true);
            System.out.print(curveName + " swap G1G2 n=" + n + " m=" + m);
            int matrixIdx = matrixIndex(n, m);
            if (tscnmsgg.get(SNToIdx.get(schemeName)).get(matrixIdx) != null) {
                testFunc(tscnmsgg.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, matrixPolicyCase(n, m));
            }
        }
    }

    @AfterAll
    static void endTest() {
        try {
            for (int i = 0; i < tsc.size(); ++i) {
                closeWriter(tsc.get(i));
                closeWriter(tscsgg.get(i));
                closeWriterList(tscnm.get(i));
                closeWriterList(tscnmsgg.get(i));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void closeWriter(BufferedWriter writer) throws IOException {
        if (writer != null) writer.close();
    }

    private static void closeWriterList(List<BufferedWriter> writers) throws IOException {
        if (writers == null) return;
        for (BufferedWriter writer : writers) closeWriter(writer);
    }

    private static final class PolicyCase {
        private final String formula;
        private final Set<String> satisfyingAttrs;

        private PolicyCase(String formula, Set<String> satisfyingAttrs) {
            this.formula = formula;
            this.satisfyingAttrs = satisfyingAttrs;
        }
    }
}
