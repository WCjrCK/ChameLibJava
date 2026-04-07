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
import PerformTest.RealStorageUtil;
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
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.PBC_CUSTOM;
import static EllipticCurve.Curve.CurveName.SECP256K1;

public class RealStorageTest {
    private static final String CSV_HEADER = "Curve, PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, HashValue, Randomness\n";
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
//            PBCHName.XNM_2021,
//            PBCHName.TMM_2022,
//            PBCHName.ZLW_2021,
//            PBCHName.MXN_2022
    );

    static List<CurveName> runningCurve = List.of(
            CurveName.A,
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
        for (PBCHName value : PBCHName.values()) new File(String.format("./data/PBCH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (PBCHName value : PBCHName.values()) {
                if (skipList.contains(value)) continue;

                tsc.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost.csv", value.name()), value));
                if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                    tscsgg.add(null);
                } else {
                    tscsgg.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_swapG1G2.csv", value.name()), value));
                }

                List<BufferedWriter> nmWriter = new ArrayList<>();
                List<BufferedWriter> nmSwapWriter = new ArrayList<>();
                for (int[] size : matrixSizeList) {
                    nmWriter.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_n_%d_m_%d.csv", value.name(), size[0], size[1]), value));
                    if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                        nmSwapWriter.add(null);
                    } else {
                        nmSwapWriter.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_n_%d_m_%d_swapG1G2.csv", value.name(), size[0], size[1]), value));
                    }
                }
                tscnm.add(nmWriter);
                tscnmsgg.add(nmSwapWriter);

                if (value.revocable) {
                    List<BufferedWriter> maxUserWriter = new ArrayList<>();
                    List<BufferedWriter> maxUserSwapWriter = new ArrayList<>();
                    for (int totalUser : totalUserList) {
                        maxUserWriter.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_max_user_%d.csv", value.name(), totalUser), value));
                        if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                            maxUserSwapWriter.add(null);
                        } else {
                            maxUserSwapWriter.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_max_user_%d_swapG1G2.csv", value.name(), totalUser), value));
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
                        authNumWriter.add(createWriter(String.format("./data/PBCH/%s/real_storage_cost_auth_num_%d.csv", value.name(), authorityNum), value));
                    }
                    tscauthnum.add(authNumWriter);
                } else {
                    tscauthnum.add(null);
                }

                SNToIdx.put(value, i);
                ++i;
            }
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
        return CSV_HEADER;
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

    private static Object getFieldValue(Object target, String fieldName) {
        if (target == null) return null;
        for (Class<?> current = target.getClass(); current != null && current != Object.class; current = current.getSuperclass()) {
            try {
                Field field = current.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                // Continue searching up the hierarchy.
            } catch (IllegalAccessException e) {
                throw new RuntimeException(String.format("failed to access field %s.%s", current.getName(), fieldName), e);
            }
        }
        throw new IllegalArgumentException(String.format("field %s not found in %s", fieldName, target.getClass().getName()));
    }

    private static long sizeOfNestedField(Object target, String... fieldNames) {
        Object current = target;
        for (String fieldName : fieldNames) {
            if (current == null) return 0L;
            current = getFieldValue(current, fieldName);
        }
        return RealStorageUtil.sizeOf(current);
    }

    private static long sumSizeOfNestedField(Object[] targets, String... fieldNames) {
        long total = 0L;
        for (Object target : targets) total += sizeOfNestedField(target, fieldNames);
        return total;
    }

    private void testFunc(BufferedWriter realStorageCost, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        System.out.println("Running " + schemeConfig.schemeName);
        if (schemeConfig.schemeName.has_blackbox_accountability) testBAPBCH(realStorageCost, schemeConfig, policyCaseGenerator);
        else if (schemeConfig.schemeName.revocable) testRevocablePBCH(realStorageCost, schemeConfig, policyCaseGenerator);
        else if (schemeConfig.schemeName.multi_auth) testMAPBCH(realStorageCost, schemeConfig, policyCaseGenerator);
        else testBasePBCH(realStorageCost, schemeConfig, policyCaseGenerator);
    }

    private void testBasePBCH(BufferedWriter realStorageCost, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(pp, mpk, msk);

        PolicyCase policyCase = policyCaseGenerator.generate();
        Policy policy = pp.createPolicy(policyCase.formula);
        Attributes attrs = pp.createAttributes();
        addAttrs(attrs, policyCase.satisfyingAttrs);

        SecretKey sk = pp.createSecretKey();
        scheme.KeyGen(sk, pp, mpk, msk, attrs);

        HashValue h = pp.createHashValue();
        Randomness r = pp.createRandomness();
        Message m = pp.createMessage("msg");
        scheme.Hash(h, r, pp, mpk, m, policy);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                RealStorageUtil.sizeOf(mpk),
                RealStorageUtil.sizeOf(msk),
                RealStorageUtil.sizeOf(sk),
                RealStorageUtil.sizeOf(policy),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    private void testBAPBCH(BufferedWriter realStorageCost, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        BAPBCH scheme = BAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.BAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(pp, mpk, msk);

        PolicyCase policyCase = policyCaseGenerator.generate();
        Policy policy = pp.createPolicy(policyCase.formula);

        User user = pp.createUser(Math.max(1, ((int) schemeConfig.params.get("id_len")) / 3));
        scheme.AssignUser(user, pp, mpk, msk);
        addAttrs(user.S, policyCase.satisfyingAttrs);
        scheme.KeyGen(user, pp, mpk, msk);

        HashValue h = pp.createHashValue();
        Randomness r = pp.createRandomness();
        Message m = pp.createMessage("msg");
        scheme.Hash(h, r, pp, mpk, user, m, policy);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                RealStorageUtil.sizeOf(mpk),
                RealStorageUtil.sizeOf(msk),
                RealStorageUtil.sizeOf(user.sk),
                RealStorageUtil.sizeOf(policy),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    private void testRevocablePBCH(BufferedWriter realStorageCost, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        RevocablePBCH scheme = RevocablePBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey mpk = pp.createMasterPublicKey();
        ChameleonHash.PBCH.RevocablePBCH.Components.Authority auth = pp.createAuthority();
        auth.Setup(mpk, pp);

        PolicyCase policyCase = policyCaseGenerator.generate();
        ChameleonHash.PBCH.RevocablePBCH.Components.User user = pp.createUser("user");
        addAttrs(user.S, policyCase.satisfyingAttrs);
        ChameleonHash.PBCH.RevocablePBCH.Components.Policy policy = pp.createPolicy(policyCase.formula);
        ChameleonHash.PBCH.RevocablePBCH.Components.Info info = pp.createInfo();
        setTimestamp(info, 20);

        auth.KeyGen(user, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Message m = pp.createMessage("msg");
        user.Hash(h, r, pp, mpk, m, policy, info);

        auth.KeyUpdate(pp, mpk, info);
        auth.DecryptKeyGen(user, pp, mpk);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                RealStorageUtil.sizeOf(mpk),
                RealStorageUtil.sizeOf(auth.msk),
                RealStorageUtil.sizeOf(user.sk),
                RealStorageUtil.sizeOf(policy),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    private void testMAPBCH(BufferedWriter realStorageCost, PBCHConfig schemeConfig, PolicyCaseGenerator policyCaseGenerator) throws IOException {
        MAPBCH scheme = MAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.MAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);

        int authNum = (int) schemeConfig.params.getOrDefault("authority_num", DEFAULT_AUTHORITY_NUM);
        PolicyCase policyCase = policyCaseGenerator.generate();
        ChameleonHash.PBCH.MAPBCH.Components.Policy policy = pp.createPolicy(policyCase.formula);
        ChameleonHash.PBCH.MAPBCH.Components.User user = pp.createUser("user");
        ChameleonHash.PBCH.MAPBCH.Components.Authority[] authorities = new ChameleonHash.PBCH.MAPBCH.Components.Authority[authNum];
        for (int i = 0; i < authNum; ++i) {
            authorities[i] = pp.createAuthority();
            authorities[i].Setup(pp);
        }

        assignPolicyAttrsToAuthorities(pp, authorities, extractPolicyAttrs(policyCase.formula));
        user.Setup(pp);
        addAttrs(user, pp, policyCase.satisfyingAttrs);
        for (int i = 0; i < authNum; ++i) user.KeyGen(pp, authorities[i]);

        ChameleonHash.PBCH.MAPBCH.Components.HashValue h = pp.createHashValue();
        ChameleonHash.PBCH.MAPBCH.Components.Randomness r = pp.createRandomness();
        ChameleonHash.PBCH.MAPBCH.Components.Message m = pp.createMessage("msg");
        user.Hash(h, r, pp, policy, m);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                sumSizeOfNestedField(authorities, "MAABE_auth", "apk"),
                sumSizeOfNestedField(authorities, "MAABE_auth", "ask"),
                sizeOfNestedField(user, "MAABE_user", "skg"),
                RealStorageUtil.sizeOf(policy),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    @DisplayName("test PBCH real storage cost")
    @Nested
    class PBCHRSCTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllPBCHSchemeCurve")
        public void DSTest(PBCHName schemeName, CurveName curveName) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false);
            if (tsc.get(SNToIdx.get(schemeName)) != null) {
                testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig, RealStorageTest::defaultPerformancePolicyCase);
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllPBCHSchemeASCurve")
        public void SGGTest(PBCHName schemeName, CurveName curveName) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true);
            if (tscsgg.get(SNToIdx.get(schemeName)) != null) {
                testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig, RealStorageTest::defaultPerformancePolicyCase);
            }
        }
    }

    @DisplayName("test PBCH real storage cost diff matrix size")
    @Nested
    class PBCHRSCMatTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with n {2} m {3}")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllPBCHSchemeCurveMatrixNM")
        public void DSTest(PBCHName schemeName, CurveName curveName, int n, int m) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false);
            int matrixIdx = matrixIndex(n, m);
            if (tscnm.get(SNToIdx.get(schemeName)).get(matrixIdx) != null) {
                testFunc(tscnm.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, () -> matrixPolicyCase(n, m));
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with n {2} m {3} and swap G1 G2")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllPBCHSchemeASCurveMatrixNM")
        public void SGGTest(PBCHName schemeName, CurveName curveName, int n, int m) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true);
            int matrixIdx = matrixIndex(n, m);
            if (tscnmsgg.get(SNToIdx.get(schemeName)).get(matrixIdx) != null) {
                testFunc(tscnmsgg.get(SNToIdx.get(schemeName)).get(matrixIdx), schemeConfig, () -> matrixPolicyCase(n, m));
            }
        }
    }

    @DisplayName("test RPBCH real storage cost diff max user")
    @Nested
    class PBCHRSCMaxUserTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with max_user {2}")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllRPBCHSchemeCurveTotalUser")
        public void DSTest(PBCHName schemeName, CurveName curveName, int totalUser) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, totalUser);
            int totalUserIdx = totalUserIndex(totalUser);
            if (tscmaxuser.get(SNToIdx.get(schemeName)) != null && tscmaxuser.get(SNToIdx.get(schemeName)).get(totalUserIdx) != null) {
                testFunc(tscmaxuser.get(SNToIdx.get(schemeName)).get(totalUserIdx), schemeConfig, RealStorageTest::defaultPerformancePolicyCase);
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with max_user {2} and swap G1 G2")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllRPBCHSchemeASCurveTotalUser")
        public void SGGTest(PBCHName schemeName, CurveName curveName, int totalUser) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, true, totalUser);
            int totalUserIdx = totalUserIndex(totalUser);
            if (tscmaxusersgg.get(SNToIdx.get(schemeName)) != null && tscmaxusersgg.get(SNToIdx.get(schemeName)).get(totalUserIdx) != null) {
                testFunc(tscmaxusersgg.get(SNToIdx.get(schemeName)).get(totalUserIdx), schemeConfig, RealStorageTest::defaultPerformancePolicyCase);
            }
        }
    }

    @DisplayName("test MAPBCH real storage cost diff authority num")
    @Nested
    class PBCHRSCAuthorityNumTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with authority_num {2}")
        @MethodSource("PerformTest.PBCH.RealStorageTest#GetAllMAPBCHSchemeCurveAuthorityNum")
        public void DSTest(PBCHName schemeName, CurveName curveName, int authorityNum) throws IOException {
            PBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, 2048, authorityNum);
            int authorityNumIdx = authorityNumIndex(authorityNum);
            if (tscauthnum.get(SNToIdx.get(schemeName)) != null && tscauthnum.get(SNToIdx.get(schemeName)).get(authorityNumIdx) != null) {
                testFunc(tscauthnum.get(SNToIdx.get(schemeName)).get(authorityNumIdx), schemeConfig, RealStorageTest::defaultPerformancePolicyCase);
            }
        }
    }

    @AfterAll
    static void endTest() {
        try {
            for (int i = 0; i < tsc.size(); ++i) {
                RealStorageUtil.closeWriter(tsc.get(i));
                RealStorageUtil.closeWriter(tscsgg.get(i));
                RealStorageUtil.closeWriterList(tscnm.get(i));
                RealStorageUtil.closeWriterList(tscnmsgg.get(i));
                RealStorageUtil.closeWriterList(tscmaxuser.get(i));
                RealStorageUtil.closeWriterList(tscmaxusersgg.get(i));
                RealStorageUtil.closeWriterList(tscauthnum.get(i));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
