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
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEName;
import PerformTest.RealStorageUtil;
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

public class RealStorageTest {
    static List<BufferedWriter> tsc = new ArrayList<>();
    static List<BufferedWriter> tscsgg = new ArrayList<>();
    static List<BufferedWriter> tscsgG1 = new ArrayList<>();
    static List<BufferedWriter> tscsgG2 = new ArrayList<>();
    static List<BufferedWriter> tscsgGT = new ArrayList<>();
    static HashMap<CHName, Integer> SNToIdx = new HashMap<>();

    static List<CHName> skipList = List.of(
//            CHName.CCT_2024,
//            CHName.DKS_2020,
//            CHName.LLA_2012,
//            CHName.CZT_2011,
//            CHName.CZK_2004,
//            CHName.AM_2004,
//            CHName.KOG_CDK_2017,
//            CHName.DSS_2020
    );

    static List<CurveName> runningCurve = List.of(
            CurveName.A,
            CurveName.A1,
            CurveName.E,
            CurveName.D_224,
            CurveName.BN254
    );

    public static Stream<Arguments> GetAllCHSchemeCurve() {
        return EnumSet.allOf(CHName.class).stream()
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

    public static Stream<Arguments> GetAllCHSchemeASCurve() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.ALL)
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

    public static Stream<Arguments> GetAllCHSchemeSingleGroup() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
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
        for (CHName value : CHName.values()) new File(String.format("./data/CH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (CHName value : CHName.values()) {
                if (skipList.contains(value)) continue;
                if (value.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP) {
                    tsc.add(createWriter(String.format("./data/CH/%s/real_storage_cost.csv", value.name()), value));
                } else {
                    tsc.add(null);
                }

                if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC || value.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP) {
                    tscsgg.add(null);
                } else {
                    tscsgg.add(createWriter(String.format("./data/CH/%s/real_storage_cost_swapG1G2.csv", value.name()), value));
                }

                if (value.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP) {
                    tscsgG1.add(createWriter(String.format("./data/CH/%s/real_storage_cost_inG1.csv", value.name()), value));
                    tscsgG2.add(createWriter(String.format("./data/CH/%s/real_storage_cost_inG2.csv", value.name()), value));
                    tscsgGT.add(createWriter(String.format("./data/CH/%s/real_storage_cost_inGT.csv", value.name()), value));
                } else {
                    tscsgG1.add(null);
                    tscsgG2.add(null);
                    tscsgGT.add(null);
                }

                SNToIdx.put(value, i);
                ++i;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static BufferedWriter createWriter(String path, CHName schemeName) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(path));
        writer.write(getCsvHeader(schemeName));
        return writer;
    }

    private static String getCsvHeader(CHName schemeName) {
        if (schemeName.has_label) return "Curve, PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness\n";
        if (schemeName.has_ET) return "Curve, PublicParam, PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness\n";
        return "Curve, PublicParam, PublicKey, SecretKey, Message, HashValue, Randomness\n";
    }

    private static CHConfig buildConfig(CHName schemeName, CurveName curveName, boolean swapG1G2) {
        return buildConfig(schemeName, curveName, swapG1G2, null);
    }

    private static CHConfig buildConfig(CHName schemeName, CurveName curveName, boolean swapG1G2, CurveGroup curveGroup) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curveParam = new HashMap<>();
        curveParam.put("swap_G1G2", swapG1G2);
        if (curveGroup != null) params.put("curve_group", curveGroup);
        params.put("pke_config", new PKEConfig(PKEName.RSA));

        Config curveConfig = new Config(curveName, curveParam);
        CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
        params.put("ch_config", BC_CH);
        return new CHConfig(schemeName, curveConfig, params);
    }

    @DisplayName("test CH real storage cost")
    @Nested
    class CHRSCTest {
        private void testFunc(BufferedWriter realStorageCost, CHConfig schemeConfig) throws IOException {
            System.out.println("Running " + schemeConfig.schemeName);
            if (schemeConfig.schemeName.has_label) testLabelCH(realStorageCost, schemeConfig);
            else if (schemeConfig.schemeName.has_ET) testCHET(realStorageCost, schemeConfig);
            else testBaseCH(realStorageCost, schemeConfig);
        }

        private void testBaseCH(BufferedWriter realStorageCost, CHConfig schemeConfig) throws IOException {
            BaseCH scheme = BaseCHFactory.createScheme(schemeConfig);
            PublicParam pp = scheme.createPublicParam(schemeConfig);
            scheme.Setup(pp);
            System.out.println(RealStorageUtil.debugTopLevelBreakdown("pp", pp));


            PublicKey pk = pp.createPublicKey();
            SecretKey sk = pp.createSecretKey();
            scheme.KeyGen(pk, sk, pp);

            Message m = pp.createMessage("msg");
            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();
            scheme.Hash(h, r, pp, pk, m);

            RealStorageUtil.writeRow(
                    realStorageCost,
                    schemeConfig.curveConfig.curveName.name(),
                    RealStorageUtil.sizeOf(pp),
                    RealStorageUtil.sizeOf(pk),
                    RealStorageUtil.sizeOf(sk),
                    RealStorageUtil.sizeOf(m),
                    RealStorageUtil.sizeOf(h),
                    RealStorageUtil.sizeOf(r)
            );
        }

        private void testCHET(BufferedWriter realStorageCost, CHConfig schemeConfig) throws IOException {
            CHET scheme = CHETFactory.createScheme(schemeConfig);
            ChameleonHash.CH.CHET.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            scheme.Setup(pp);

            ChameleonHash.CH.CHET.Components.PublicKey pk = pp.createPublicKey();
            ChameleonHash.CH.CHET.Components.SecretKey sk = pp.createSecretKey();
            scheme.KeyGen(pk, sk, pp);

            ChameleonHash.CH.CHET.Components.Message m = pp.createMessage("msg");
            ChameleonHash.CH.CHET.Components.HashValue h = pp.createHashValue();
            ChameleonHash.CH.CHET.Components.Randomness r = pp.createRandomness();
            ChameleonHash.CH.CHET.Components.ETrapdoor etd = pp.createETrapdoor();
            scheme.Hash(h, r, etd, pp, pk, m);

            RealStorageUtil.writeRow(
                    realStorageCost,
                    schemeConfig.curveConfig.curveName.name(),
                    RealStorageUtil.sizeOf(pp),
                    RealStorageUtil.sizeOf(pk),
                    RealStorageUtil.sizeOf(sk),
                    RealStorageUtil.sizeOf(m),
                    RealStorageUtil.sizeOf(etd),
                    RealStorageUtil.sizeOf(h),
                    RealStorageUtil.sizeOf(r)
            );
        }

        private void testLabelCH(BufferedWriter realStorageCost, CHConfig schemeConfig) throws IOException {
            LabelCH scheme = LabelCHFactory.createScheme(schemeConfig);
            ChameleonHash.CH.LabelCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            scheme.Setup(pp);

            ChameleonHash.CH.LabelCH.Components.PublicKey pk = pp.createPublicKey();
            ChameleonHash.CH.LabelCH.Components.SecretKey sk = pp.createSecretKey();
            scheme.KeyGen(pk, sk, pp);

            ChameleonHash.CH.LabelCH.Components.Message m = pp.createMessage("msg");
            ChameleonHash.CH.LabelCH.Components.Label l = pp.createLabel("label");
            ChameleonHash.CH.LabelCH.Components.HashValue h = pp.createHashValue();
            ChameleonHash.CH.LabelCH.Components.Randomness r = pp.createRandomness();
            scheme.Hash(h, r, pp, pk, m, l);

            RealStorageUtil.writeRow(
                    realStorageCost,
                    schemeConfig.curveConfig.curveName.name(),
                    RealStorageUtil.sizeOf(pp),
                    RealStorageUtil.sizeOf(pk),
                    RealStorageUtil.sizeOf(sk),
                    RealStorageUtil.sizeOf(m),
                    RealStorageUtil.sizeOf(l),
                    RealStorageUtil.sizeOf(h),
                    RealStorageUtil.sizeOf(r)
            );
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.CH.RealStorageTest#GetAllCHSchemeCurve")
        public void DSTest(CHName schemeName, CurveName curveName) throws IOException {
            CHConfig schemeConfig = buildConfig(schemeName, curveName, false);
            if (tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.CH.RealStorageTest#GetAllCHSchemeASCurve")
        public void SGGTest(CHName schemeName, CurveName curveName) throws IOException {
            CHConfig schemeConfig = buildConfig(schemeName, curveName, true);
            if (tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("test single group scheme")
        @ParameterizedTest(name = "test scheme {0} curve {1} group {2}")
        @MethodSource("PerformTest.CH.RealStorageTest#GetAllCHSchemeSingleGroup")
        void CHSingleGroupTest(CHName schemeName, CurveName curveName, CurveGroup curveGroup) throws IOException {
            CHConfig schemeConfig = buildConfig(schemeName, curveName, false, curveGroup);
            switch (curveGroup) {
                case G1:
                    if (tscsgG1.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgG1.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
                case G2:
                    if (tscsgG2.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgG2.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
                case GT:
                    if (tscsgGT.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgGT.get(SNToIdx.get(schemeName)), schemeConfig);
                    break;
                default:
                    break;
            }
        }
    }

    @AfterAll
    static void endTest() {
        try {
            for (int i = 0; i < tsc.size(); ++i) {
                RealStorageUtil.closeWriter(tsc.get(i));
                RealStorageUtil.closeWriter(tscsgg.get(i));
                RealStorageUtil.closeWriter(tscsgG1.get(i));
                RealStorageUtil.closeWriter(tscsgG2.get(i));
                RealStorageUtil.closeWriter(tscsgGT.get(i));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
