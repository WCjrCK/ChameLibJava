package PerformTest.IBCH;

import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.BaseIBCH.Components.*;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.IBCH.IBCHName;
import ChameleonHash.IBCH.LabelIBCH.LabelIBCHFactory;
import ChameleonHash.Interface.BaseIBCH;
import ChameleonHash.Interface.LabelIBCH;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveName;
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
    static List<List<BufferedWriter>> tscDiffId = new ArrayList<>();
    static List<List<BufferedWriter>> tscDiffIdSgg = new ArrayList<>();
    static HashMap<IBCHName, Integer> SNToIdx = new HashMap<>();

    static List<IBCHName> skipList = List.of(
            IBCHName.ZSS_2003_S1,
            IBCHName.ZSS_2003_S2,
            IBCHName.CZS_2014,
            IBCHName.LSX_2022
//            IBCHName.XSL_2021
//            IBCHName.LJF_2025
    );

    static List<IBCHName> diffIdList = List.of(
            IBCHName.XSL_2021
    );

    static List<CurveName> runningCurve = List.of(
            CurveName.A,
            CurveName.A1,
            CurveName.E,
            CurveName.D_224,
            CurveName.F,
            CurveName.SM_9,
            CurveName.G_149,
            CurveName.BN254,
            CurveName.BLS12_381
    );

    static List<Integer> testIdLen = List.of(512, 1024, 2048, 4096, 8192);

    public static Stream<Arguments> GetAllIBCHSchemeCurve() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1 && b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllIBCHSchemeASCurve() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1 && b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllIBCHSchemeCurveDiffIDLen() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(diffIdList::contains)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1 && b != PBC_CUSTOM)
                                .filter(a::checkCurve)
                                .flatMap(b -> testIdLen.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c))))
                );
    }

    public static Stream<Arguments> GetAllIBCHSchemeASCurveDiffIDLen() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(diffIdList::contains)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(runningCurve::contains)
                                .filter(b -> b != SECP256K1 && b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> testIdLen.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c))))
                );
    }

    @BeforeAll
    static void initTest() {
        for (IBCHName value : IBCHName.values()) new File(String.format("./data/IBCH/%s", value.name())).mkdirs();
        try {
            int i = 0;
            for (IBCHName value : IBCHName.values()) {
                if (skipList.contains(value)) continue;
                tsc.add(createWriter(String.format("./data/IBCH/%s/real_storage_cost.csv", value.name()), value));
                if (value.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                    tscsgg.add(null);
                } else {
                    tscsgg.add(createWriter(String.format("./data/IBCH/%s/real_storage_cost_swapG1G2.csv", value.name()), value));
                }

                if (diffIdList.contains(value)) {
                    List<BufferedWriter> writers = new ArrayList<>();
                    List<BufferedWriter> swapWriters = new ArrayList<>();
                    for (int idLen : testIdLen) {
                        writers.add(createWriter(String.format("./data/IBCH/%s/real_storage_cost_idlen_%d.csv", value.name(), idLen), value));
                        swapWriters.add(createWriter(String.format("./data/IBCH/%s/real_storage_cost_idlen_%d_swapG1G2.csv", value.name(), idLen), value));
                    }
                    tscDiffId.add(writers);
                    tscDiffIdSgg.add(swapWriters);
                } else {
                    tscDiffId.add(null);
                    tscDiffIdSgg.add(null);
                }

                SNToIdx.put(value, i);
                ++i;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static BufferedWriter createWriter(String path, IBCHName schemeName) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(path));
        writer.write(getCsvHeader(schemeName));
        return writer;
    }

    private static String getCsvHeader(IBCHName schemeName) {
        if (schemeName.has_label) return "Curve, PublicParam, MasterSecretKey, SecretKey, Identity, Message, Label, HashValue, Randomness\n";
        return "Curve, PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness\n";
    }

    private static IBCHConfig buildConfig(IBCHName schemeName, CurveName curveName, boolean swapG1G2, int idLen) {
        Map<String, Object> params = new HashMap<>();
        params.put("ID_Binary_Len", idLen);
        Map<String, Object> curveParam = new HashMap<>();
        curveParam.put("swap_G1G2", swapG1G2);
        Config curveConfig = new Config(curveName, curveParam);
        return new IBCHConfig(schemeName, curveConfig, params);
    }

    private void testFunc(BufferedWriter realStorageCost, IBCHConfig schemeConfig) throws IOException {
        System.out.println("Running " + schemeConfig.schemeName);
        if (schemeConfig.schemeName.has_label) testLabelIBCH(realStorageCost, schemeConfig);
        else testBaseIBCH(realStorageCost, schemeConfig);
    }

    private void testBaseIBCH(BufferedWriter realStorageCost, IBCHConfig schemeConfig) throws IOException {
        BaseIBCH scheme = BaseIBCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(pp, msk);

        SecretKey sk = pp.createSecretKey();
        Identity id = pp.createIdentity("ID1");
        scheme.KeyGen(sk, pp, msk, id);

        Message m = pp.createMessage("msg");
        HashValue h = pp.createHashValue();
        Randomness r = pp.createRandomness();
        scheme.Hash(h, r, pp, id, m);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                RealStorageUtil.sizeOf(msk),
                RealStorageUtil.sizeOf(sk),
                RealStorageUtil.sizeOf(id),
                RealStorageUtil.sizeOf(m),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    private void testLabelIBCH(BufferedWriter realStorageCost, IBCHConfig schemeConfig) throws IOException {
        LabelIBCH scheme = LabelIBCHFactory.createScheme(schemeConfig);
        ChameleonHash.IBCH.LabelIBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.IBCH.LabelIBCH.Components.MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(pp, msk);

        ChameleonHash.IBCH.LabelIBCH.Components.SecretKey sk = pp.createSecretKey();
        ChameleonHash.IBCH.LabelIBCH.Components.Identity id = pp.createIdentity("ID1");
        scheme.KeyGen(sk, pp, msk, id);

        ChameleonHash.IBCH.LabelIBCH.Components.Message m = pp.createMessage("msg");
        ChameleonHash.IBCH.LabelIBCH.Components.Label l = pp.createLabel("label");
        ChameleonHash.IBCH.LabelIBCH.Components.HashValue h = pp.createHashValue();
        ChameleonHash.IBCH.LabelIBCH.Components.Randomness r = pp.createRandomness();
        scheme.Hash(h, r, pp, id, m, l);

        RealStorageUtil.writeRow(
                realStorageCost,
                schemeConfig.curveConfig.curveName.name(),
                RealStorageUtil.sizeOf(pp),
                RealStorageUtil.sizeOf(msk),
                RealStorageUtil.sizeOf(sk),
                RealStorageUtil.sizeOf(id),
                RealStorageUtil.sizeOf(m),
                RealStorageUtil.sizeOf(l),
                RealStorageUtil.sizeOf(h),
                RealStorageUtil.sizeOf(r)
        );
    }

    @DisplayName("test IBCH real storage cost")
    @Nested
    class IBCHRSCTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1}")
        @MethodSource("PerformTest.IBCH.RealStorageTest#GetAllIBCHSchemeCurve")
        public void DSTest(IBCHName schemeName, CurveName curveName) throws IOException {
            IBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, 64);
            if (tsc.get(SNToIdx.get(schemeName)) != null) testFunc(tsc.get(SNToIdx.get(schemeName)), schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with swap G1 and G2")
        @MethodSource("PerformTest.IBCH.RealStorageTest#GetAllIBCHSchemeASCurve")
        public void SGGTest(IBCHName schemeName, CurveName curveName) throws IOException {
            IBCHConfig schemeConfig = buildConfig(schemeName, curveName, true, 64);
            if (tscsgg.get(SNToIdx.get(schemeName)) != null) testFunc(tscsgg.get(SNToIdx.get(schemeName)), schemeConfig);
        }
    }

    @DisplayName("test IBCH real storage cost diff ID len")
    @Nested
    class IBCHRSCIDLenTest {
        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with id_len {2}")
        @MethodSource("PerformTest.IBCH.RealStorageTest#GetAllIBCHSchemeCurveDiffIDLen")
        public void DSTest(IBCHName schemeName, CurveName curveName, int idLen) throws IOException {
            IBCHConfig schemeConfig = buildConfig(schemeName, curveName, false, idLen);
            int idx = testIdLen.indexOf(idLen);
            if (tscDiffId.get(SNToIdx.get(schemeName)) != null && tscDiffId.get(SNToIdx.get(schemeName)).get(idx) != null) {
                testFunc(tscDiffId.get(SNToIdx.get(schemeName)).get(idx), schemeConfig);
            }
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0} in curve {1} with id_len {2} with swap G1 and G2")
        @MethodSource("PerformTest.IBCH.RealStorageTest#GetAllIBCHSchemeASCurveDiffIDLen")
        public void SGGTest(IBCHName schemeName, CurveName curveName, int idLen) throws IOException {
            IBCHConfig schemeConfig = buildConfig(schemeName, curveName, true, idLen);
            int idx = testIdLen.indexOf(idLen);
            if (tscDiffIdSgg.get(SNToIdx.get(schemeName)) != null && tscDiffIdSgg.get(SNToIdx.get(schemeName)).get(idx) != null) {
                testFunc(tscDiffIdSgg.get(SNToIdx.get(schemeName)).get(idx), schemeConfig);
            }
        }
    }

    @AfterAll
    static void endTest() {
        try {
            for (int i = 0; i < tsc.size(); ++i) {
                RealStorageUtil.closeWriter(tsc.get(i));
                RealStorageUtil.closeWriter(tscsgg.get(i));
                RealStorageUtil.closeWriterList(tscDiffId.get(i));
                RealStorageUtil.closeWriterList(tscDiffIdSgg.get(i));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
