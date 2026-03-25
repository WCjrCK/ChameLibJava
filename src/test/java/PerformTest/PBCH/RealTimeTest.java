package PerformTest.PBCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.Interface.MAPBCH;
import ChameleonHash.Interface.RevocablePBCH;
import ChameleonHash.PBCH.BAPBCH.BAPBCHFactory;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.MAPBCH.MAPBCHFactory;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.PBCH.RevocablePBCH.RevocablePBCHFactory;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.utils.BooleanFormulaParser;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
import Signature.SConfig;
import Signature.SName;
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
    private static final int DEFAULT_POLICY_MATRIX_N = 64;
    private static final int DEFAULT_POLICY_MATRIX_M = 32;
    private static final int DEFAULT_AUTHORITY_NUM = 4;

    static List<BufferedWriter> tsc = new ArrayList<>();
    static List<BufferedWriter> tscsgg = new ArrayList<>();
    static List<List<BufferedWriter>> tscnm = new ArrayList<>();
    static List<List<BufferedWriter>> tscnmsgg = new ArrayList<>();
    static List<List<BufferedWriter>> tscmaxuser = new ArrayList<>();
    static List<List<BufferedWriter>> tscmaxusersgg = new ArrayList<>();
    static List<List<BufferedWriter>> tscauthnum = new ArrayList<>();
    static HashMap<PBCHName, Integer> SNToIdx = new HashMap<>();

    static List<PBCHName> skipList = List.of(
//            PBCHName.DSS_2019,
//            PBCHName.TLL_2020,
            PBCHName.XNM_2021,
            PBCHName.TMM_2022,
            PBCHName.ZLW_2021,
            PBCHName.MXN_2022
    );

    static List<CurveName> runningCurve = List.of(
            CurveName.A,
//            CurveName.A1,
//            CurveName.E,
            CurveName.D_224,
            CurveName.BN254
    );

    static List<int[]> matrixSizeList = List.of(
            new int[]{64, 10},
            new int[]{64, 20},
            new int[]{64, 30},
            new int[]{64, 40},
            new int[]{64, 50},
            new int[]{10, 5},
            new int[]{20, 5},
            new int[]{30, 5},
            new int[]{40, 5},
            new int[]{50, 5}
    );

    static List<Integer> totalUserList = List.of(512, 1024, 2048, 4096, 8192);
    static List<Integer> authorityNumList = List.of(4, 8, 16, 32, 64);

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

    public static Stream<Arguments> GetAllRPBCHSchemeCurveTotalUser() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.revocable)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> totalUserList.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c))))
                );
    }

    public static Stream<Arguments> GetAllRPBCHSchemeASCurveTotalUser() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.revocable)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> totalUserList.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c))))
                );
    }

    public static Stream<Arguments> GetAllMAPBCHSchemeCurveAuthorityNum() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.multi_auth)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> authorityNumList.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c))))
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

                if (value.revocable) {
                    List<BufferedWriter> maxUserWriter = new ArrayList<>();
                    List<BufferedWriter> maxUserSwapWriter = new ArrayList<>();
                    for (int totalUser : totalUserList) {
                        maxUserWriter.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_max_user_%d_%d.csv", value.name(), totalUser, repeat_cnt), value));
                        if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                            maxUserSwapWriter.add(null);
                        } else {
                            maxUserSwapWriter.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_max_user_%d_swapG1G2_%d.csv", value.name(), totalUser, repeat_cnt), value));
                        }
                    }
                    tscmaxuser.add(maxUserWriter);
                    tscmaxusersgg.add(maxUserSwapWriter);
                } else {
                    tscmaxuser.add(null);
                    tscmaxusersgg.add(null);
                }

                if (value.multi_auth) {
                    List<BufferedWriter> authNumWriter = new ArrayList<>();
                    for (int authorityNum : authorityNumList) {
                        authNumWriter.add(createWriter(String.format("./data/PBCH/%s/real_time_cost_auth_num_%d_%d.csv", value.name(), authorityNum, repeat_cnt), value));
                    }
                    tscauthnum.add(authNumWriter);
                } else {
                    tscauthnum.add(null);
                }

                SNToIdx.put(value, i);
                ++i;
            }
            System.out.println("\t\t\tSee CSV header for detailed timing columns");
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
        if (schemeName.revocable) return "Curve, SetUp, KeyGen, KeyUpdate, DecryptKeyGen, Hash, Ver, Col, Revoke\n";
        if (schemeName.has_blackbox_accountability) return "Curve, SetUp, AssignUser, KeyGen, Hash, Ver, Col\n";
        if (schemeName.multi_auth) return "Curve, SetUp, AuthSetUp, UserSetUp, KeyGen, Hash, Ver, Col\n";
        return "Curve, SetUp, KeyGen, Hash, Ver, Col\n";
    }

    private static PBCHConfig buildConfig(PBCHName schemeName, CurveName curveName, boolean swapG1G2) {
        return buildConfig(schemeName, curveName, swapG1G2, 2048, DEFAULT_AUTHORITY_NUM);
    }

    private static PBCHConfig buildConfig(PBCHName schemeName, CurveName curveName, boolean swapG1G2, int maxUser) {
        return buildConfig(schemeName, curveName, swapG1G2, maxUser, DEFAULT_AUTHORITY_NUM);
    }

    private static PBCHConfig buildConfig(PBCHName schemeName, CurveName curveName, boolean swapG1G2, int maxUser, int authorityNum) {
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
        params.put("max_user", maxUser);
        params.put("authority_num", authorityNum);
        params.put("curve_group", CurveGroup.G1);
        if (schemeName.multi_auth) params.put("maabe_config", new ABEConfig(ABEName.MAABE_RW_2015, curveConfig));
        if (schemeName == PBCHName.MXN_2022) params.put("ds_config", new SConfig(SName.BLS, curveConfig));
        return new PBCHConfig(schemeName, curveConfig, params);
    }

    private static PolicyCase defaultPerformancePolicyCase() {
        return matrixPolicyCase(DEFAULT_POLICY_MATRIX_N, DEFAULT_POLICY_MATRIX_M);
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

    private static int totalUserIndex(int totalUser) {
        int idx = totalUserList.indexOf(totalUser);
        if (idx >= 0) return idx;
        throw new IllegalArgumentException(String.format("unsupported max_user=%d", totalUser));
    }

    private static int authorityNumIndex(int authorityNum) {
        int idx = authorityNumList.indexOf(authorityNum);
        if (idx >= 0) return idx;
        throw new IllegalArgumentException(String.format("unsupported authority_num=%d", authorityNum));
    }

    private static void addAttrs(Attributes attrs, Set<String> satisfyingAttrs) {
        for (String attr : satisfyingAttrs) attrs.addAttr(attr);
    }

    private static void addAttrs(ChameleonHash.PBCH.RevocablePBCH.Components.Attributes attrs, Set<String> satisfyingAttrs) {
        for (String attr : satisfyingAttrs) attrs.addAttr(attr);
    }

    private static void addAttrs(ChameleonHash.PBCH.MAPBCH.Components.User user, ChameleonHash.PBCH.MAPBCH.Components.PublicParam pp, Set<String> satisfyingAttrs) {
        for (String attr : satisfyingAttrs) user.AddAttr(pp.createAttribute(attr));
    }

    private static Set<String> extractPolicyAttrs(String formula) {
        Set<String> attrs = new LinkedHashSet<>();
        for (String token : formula.split("[()&|]+")) {
            if (!token.isEmpty()) attrs.add(token);
        }
        return attrs;
    }

    private static void assignPolicyAttrsToAuthorities(
            ChameleonHash.PBCH.MAPBCH.Components.PublicParam pp,
            ChameleonHash.PBCH.MAPBCH.Components.Authority[] authorities,
            Set<String> policyAttrs
    ) {
        int idx = 0;
        for (String attr : policyAttrs) {
            authorities[idx % authorities.length].AddAttr(pp.createAttribute(attr));
            ++idx;
        }
    }

    private static void setTimestamp(ChameleonHash.PBCH.RevocablePBCH.Components.Info info, int timestamp) {
        HashMap<String, Object> value = new HashMap<>();
        value.put("timestamp", timestamp);
        info.setValue(value);
    }

    private static double avgMillis(long totalNanoTime) {
        return totalNanoTime / 1.0e6 / repeat_cnt;
    }

    private static void writeTimeCost(BufferedWriter realTimeTest, double[] timeCost) throws IOException {
        for (double x : timeCost) realTimeTest.write(String.format(",%.6f", x));
        realTimeTest.write("\n");
        for (double x : timeCost) System.out.printf(",%.6f", x);
        System.out.println();
        realTimeTest.flush();
    }

    private void testFunc(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        System.out.println("Running " + schemeConfig.schemeName);
        if (schemeConfig.schemeName.has_blackbox_accountability) testBAPBCH(realTimeTest, schemeConfig, policyCaseGenerator);
        else if (schemeConfig.schemeName.revocable) testRevocablePBCH(realTimeTest, schemeConfig, policyCaseGenerator);
        else if (schemeConfig.schemeName.multi_auth) testMAPBCH(realTimeTest, schemeConfig, policyCaseGenerator);
        else testBasePBCH(realTimeTest, schemeConfig, policyCaseGenerator);
        realTimeTest.flush();
    }

    private void testBasePBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
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
            timeCost[++stageId] = avgMillis(end - start);
        }

        Policy[] policies = new Policy[repeat_cnt];
        Attributes[] attrs = new Attributes[repeat_cnt];
        SecretKey[] sk = new SecretKey[repeat_cnt];
        HashValue[] h = new HashValue[repeat_cnt];
        Randomness[] r = new Randomness[repeat_cnt];
        Randomness[] r_p = new Randomness[repeat_cnt];
        Message[] m = new Message[repeat_cnt];
        Message[] m_p = new Message[repeat_cnt];
        for (int i = 0; i < repeat_cnt; ++i) {
            PolicyCase policyCase = policyCaseGenerator.generate();
            policies[i] = pp.createPolicy(policyCase.formula);
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
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Hash(h[i], r[i], pp, mpk, m[i], policies[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m[i], h[i], r[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Collision(r_p[i], pp, mpk, sk[i], m[i], h[i], r[i], m_p[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m_p[i], h[i], r_p[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        writeTimeCost(realTimeTest, timeCost);
    }

    private void testBAPBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
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
            timeCost[++stageId] = avgMillis(end - start);
        }

        Policy[] policies = new Policy[repeat_cnt];
        PolicyCase[] policyCases = new PolicyCase[repeat_cnt];
        User[] users = new User[repeat_cnt];
        HashValue[] h = new HashValue[repeat_cnt];
        Randomness[] r = new Randomness[repeat_cnt];
        Randomness[] r_p = new Randomness[repeat_cnt];
        Message[] m = new Message[repeat_cnt];
        Message[] m_p = new Message[repeat_cnt];
        int userIdLen = Math.max(1, ((int) schemeConfig.params.get("id_len")) / 3);
        for (int i = 0; i < repeat_cnt; ++i) {
            policyCases[i] = policyCaseGenerator.generate();
            policies[i] = pp.createPolicy(policyCases[i].formula);
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
            timeCost[++stageId] = avgMillis(end - start);
        }

        for (int i = 0; i < repeat_cnt; ++i) addAttrs(users[i].S, policyCases[i].satisfyingAttrs);

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.KeyGen(users[i], pp, mpk, msk);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Hash(h[i], r[i], pp, mpk, users[i], m[i], policies[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m[i], h[i], r[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Collision(r_p[i], pp, mpk, msk, users[i], m[i], policies[i], h[i], r[i], m_p[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            for (int i = 0; i < repeat_cnt; ++i) res &= scheme.Verify(pp, mpk, m_p[i], h[i], r_p[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        writeTimeCost(realTimeTest, timeCost);
    }

    private void testMAPBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        realTimeTest.write(schemeConfig.curveConfig.curveName.name());
        double[] timeCost = {0, 0, 0, 0, 0, 0, 0};

        MAPBCH scheme = MAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.MAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        int authNum = (int) schemeConfig.params.getOrDefault("authority_num", DEFAULT_AUTHORITY_NUM);

        int stageId = -1;
        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) scheme.Setup(pp);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        PolicyCase[] policyCases = new PolicyCase[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Policy[] policies = new ChameleonHash.PBCH.MAPBCH.Components.Policy[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.User[] users = new ChameleonHash.PBCH.MAPBCH.Components.User[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Authority[][] authorities = new ChameleonHash.PBCH.MAPBCH.Components.Authority[repeat_cnt][authNum];
        ChameleonHash.PBCH.MAPBCH.Components.HashValue[] h = new ChameleonHash.PBCH.MAPBCH.Components.HashValue[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Randomness[] r = new ChameleonHash.PBCH.MAPBCH.Components.Randomness[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Randomness[] r_p = new ChameleonHash.PBCH.MAPBCH.Components.Randomness[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Message[] m = new ChameleonHash.PBCH.MAPBCH.Components.Message[repeat_cnt];
        ChameleonHash.PBCH.MAPBCH.Components.Message[] m_p = new ChameleonHash.PBCH.MAPBCH.Components.Message[repeat_cnt];
        for (int i = 0; i < repeat_cnt; ++i) {
            policyCases[i] = policyCaseGenerator.generate();
            policies[i] = pp.createPolicy(policyCases[i].formula);
            users[i] = pp.createUser("user_" + i);
            for (int j = 0; j < authNum; ++j) authorities[i][j] = pp.createAuthority();
            h[i] = pp.createHashValue();
            r[i] = pp.createRandomness();
            r_p[i] = pp.createRandomness();
            m[i] = pp.createMessage("msg_" + i);
            m_p[i] = pp.createMessage("msg_" + i + "_p");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i)
                for (int j = 0; j < authNum; ++j) authorities[i][j].Setup(pp);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        for (int i = 0; i < repeat_cnt; ++i) {
            assignPolicyAttrsToAuthorities(pp, authorities[i], extractPolicyAttrs(policyCases[i].formula));
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) users[i].Setup(pp);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        for (int i = 0; i < repeat_cnt; ++i) addAttrs(users[i], pp, policyCases[i].satisfyingAttrs);

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i)
                for (int j = 0; j < authNum; ++j) users[i].KeyGen(pp, authorities[i][j]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) users[i].Hash(h[i], r[i], pp, policies[i], m[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) res &= users[i].Verify(pp, m[i], h[i], r[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) users[i].Collision(r_p[i], pp, m[i], h[i], r[i], m_p[i]);
            long end = System.nanoTime();
            timeCost[++stageId] = avgMillis(end - start);
        }

        {
            boolean res = true;
            for (int i = 0; i < repeat_cnt; ++i) res &= users[i].Verify(pp, m_p[i], h[i], r_p[i]);
            assertTrue(res, "Adapt Check Failed");
        }

        writeTimeCost(realTimeTest, timeCost);
    }

    private void testRevocablePBCH(BufferedWriter realTimeTest, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        realTimeTest.write(schemeConfig.curveConfig.curveName.name());
        double[] timeCost = {0, 0, 0, 0, 0, 0, 0, 0};

        RevocablePBCH scheme = RevocablePBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey mpk = pp.createMasterPublicKey();
        ChameleonHash.PBCH.RevocablePBCH.Components.Authority auth = pp.createAuthority();

        {
            long start = System.nanoTime();
            for (int i = 0; i < repeat_cnt; ++i) auth.Setup(mpk, pp);
            long end = System.nanoTime();
            timeCost[0] = avgMillis(end - start);
        }

        ChameleonHash.PBCH.RevocablePBCH.Components.User[] users = new ChameleonHash.PBCH.RevocablePBCH.Components.User[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Policy[] policies = new ChameleonHash.PBCH.RevocablePBCH.Components.Policy[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Info[] infos = new ChameleonHash.PBCH.RevocablePBCH.Components.Info[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Info[] revokeInfos = new ChameleonHash.PBCH.RevocablePBCH.Components.Info[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue[] h = new ChameleonHash.PBCH.RevocablePBCH.Components.HashValue[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness[] r = new ChameleonHash.PBCH.RevocablePBCH.Components.Randomness[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness[] r_p = new ChameleonHash.PBCH.RevocablePBCH.Components.Randomness[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Message[] m = new ChameleonHash.PBCH.RevocablePBCH.Components.Message[repeat_cnt];
        ChameleonHash.PBCH.RevocablePBCH.Components.Message[] m_p = new ChameleonHash.PBCH.RevocablePBCH.Components.Message[repeat_cnt];

        for (int i = 0; i < repeat_cnt; ++i) {
            PolicyCase policyCase = policyCaseGenerator.generate();
            users[i] = pp.createUser("user_" + i);
            addAttrs(users[i].S, policyCase.satisfyingAttrs);
            policies[i] = pp.createPolicy(policyCase.formula);
            infos[i] = pp.createInfo();
            revokeInfos[i] = pp.createInfo();
            setTimestamp(infos[i], 20 * (i + 1));
            setTimestamp(revokeInfos[i], 20 * (i + 1) + 10);
            h[i] = pp.createHashValue();
            r[i] = pp.createRandomness();
            r_p[i] = pp.createRandomness();
            m[i] = pp.createMessage("msg_" + i);
            m_p[i] = pp.createMessage("msg_" + i + "_p");
        }

        long keyGenCost = 0;
        long keyUpdateCost = 0;
        long decryptKeyGenCost = 0;
        long hashCost = 0;
        long verifyCost = 0;
        long collisionCost = 0;
        long revokeCost = 0;
        boolean hashRes = true;
        boolean adaptRes = true;

        for (int i = 0; i < repeat_cnt; ++i) {
            long start = System.nanoTime();
            auth.KeyGen(users[i], pp, mpk);
            keyGenCost += System.nanoTime() - start;

            start = System.nanoTime();
            users[i].Hash(h[i], r[i], pp, mpk, m[i], policies[i], infos[i]);
            hashCost += System.nanoTime() - start;

            start = System.nanoTime();
            hashRes &= scheme.Verify(pp, mpk, users[i].pk, m[i], h[i], r[i]);
            verifyCost += System.nanoTime() - start;

            start = System.nanoTime();
            auth.KeyUpdate(pp, mpk, infos[i]);
            keyUpdateCost += System.nanoTime() - start;

            start = System.nanoTime();
            auth.DecryptKeyGen(users[i], pp, mpk);
            decryptKeyGenCost += System.nanoTime() - start;

            start = System.nanoTime();
            users[i].Collision(r_p[i], pp, mpk, m[i], h[i], r[i], m_p[i]);
            collisionCost += System.nanoTime() - start;

            adaptRes &= scheme.Verify(pp, mpk, users[i].pk, m_p[i], h[i], r_p[i]);

            start = System.nanoTime();
            auth.Revoke(pp, mpk, users[i], revokeInfos[i]);
            revokeCost += System.nanoTime() - start;
        }

        assertTrue(hashRes, "Hash Check Failed");
        assertTrue(adaptRes, "Adapt Check Failed");

        timeCost[1] = avgMillis(keyGenCost);
        timeCost[2] = avgMillis(keyUpdateCost);
        timeCost[3] = avgMillis(decryptKeyGenCost);
        timeCost[4] = avgMillis(hashCost);
        timeCost[5] = avgMillis(verifyCost);
        timeCost[6] = avgMillis(collisionCost);
        timeCost[7] = avgMillis(revokeCost);

        writeTimeCost(realTimeTest, timeCost);
    }

    @DisplayName("test PBCH real time cost")
    @Nested
    class PBCHRTCTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeCurve")
        public void DSTest(PBCHName schemeName, CurveName curveName) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false);
            System.out.print(curveName.name());
            if (tsc.get(SNToIdx.get(schemeName)) != null) {
                testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig, RealTimeTest::defaultPerformancePolicyCase);
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllPBCHSchemeASCurve")
        public void SGGTest(PBCHName schemeName, CurveName curveName) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true);
            System.out.print(curveName + " swap G1G2");
            if (tscsgg.get(SNToIdx.get(schemeName)) != null) {
                testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig, RealTimeTest::defaultPerformancePolicyCase);
            }
        }
    }

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
                testFunc(tscnm.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, () -> matrixPolicyCase(n, m));
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
                testFunc(tscnmsgg.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, () -> matrixPolicyCase(n, m));
            }
        }
    }

    @DisplayName("test RPBCH real time cost diff max user")
    @Nested
    class PBCHRTCMaxUserTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with max_user {2}")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllRPBCHSchemeCurveTotalUser")
        public void DSTest(PBCHName schemeName, CurveName curveName, int totalUser) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, totalUser);
            System.out.print(curveName.name() + " max_user=" + totalUser);
            int totalUserIdx = totalUserIndex(totalUser);
            if (tscmaxuser.get(SNToIdx.get(schemeName)) != null && tscmaxuser.get(SNToIdx.get(schemeName)).get(totalUserIdx) != null) {
                testFunc(tscmaxuser.get(SNToIdx.get(schemeName)).get(totalUserIdx), schemeConfig, RealTimeTest::defaultPerformancePolicyCase);
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with max_user {2} and swap G1 G2")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllRPBCHSchemeASCurveTotalUser")
        public void SGGTest(PBCHName schemeName, CurveName curveName, int totalUser) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true, totalUser);
            System.out.print(curveName + " swap G1G2 max_user=" + totalUser);
            int totalUserIdx = totalUserIndex(totalUser);
            if (tscmaxusersgg.get(SNToIdx.get(schemeName)) != null && tscmaxusersgg.get(SNToIdx.get(schemeName)).get(totalUserIdx) != null) {
                testFunc(tscmaxusersgg.get(SNToIdx.get(schemeName)).get(totalUserIdx), schemeConfig, RealTimeTest::defaultPerformancePolicyCase);
            }
        }
    }

    @DisplayName("test MAPBCH real time cost diff authority num")
    @Nested
    class PBCHRTCAuthorityNumTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with authority_num {2}")
        @MethodSource("PerformTest.PBCH.RealTimeTest#GetAllMAPBCHSchemeCurveAuthorityNum")
        public void DSTest(PBCHName schemeName, CurveName curveName, int authorityNum) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, 2048, authorityNum);
            System.out.print(curveName.name() + " authority_num=" + authorityNum);
            int authorityNumIdx = authorityNumIndex(authorityNum);
            if (tscauthnum.get(SNToIdx.get(schemeName)) != null && tscauthnum.get(SNToIdx.get(schemeName)).get(authorityNumIdx) != null) {
                testFunc(tscauthnum.get(SNToIdx.get(schemeName)).get(authorityNumIdx), schemeConfig, RealTimeTest::defaultPerformancePolicyCase);
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
                closeWriterList(tscmaxuser.get(i));
                closeWriterList(tscmaxusersgg.get(i));
                closeWriterList(tscauthnum.get(i));
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

    private interface PolicyCaseGenerator {
        PolicyCase generate();
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
