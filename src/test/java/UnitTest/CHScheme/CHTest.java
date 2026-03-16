package UnitTest.CHScheme;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.CH.CHName;
import ChameleonHash.CH.Components.*;
import ChameleonHash.CH.LabelCH.LabelCHFactory;
import ChameleonHash.Interface.BaseCH;
import ChameleonHash.Interface.CHET;
import ChameleonHash.Interface.LabelCH;
import ChameleonHash.SchemeCurveRequire;
import Commitment.NIZKConfig;
import Commitment.NIZKName;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.PBC_CUSTOM;
import static EllipticCurve.Curve.CurveName.SECP256K1;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CHTest {
    static List<CHName> skipList = List.of(new CHName[]{
            CHName.LLA_2012,
            CHName.CZT_2011,
            CHName.CZK_2004,
            CHName.CCT_2024,
            CHName.KOG_CDK_2017,
            CHName.BC_CDK_2017,
            CHName.DKS_2020,
            CHName.DSS_2020,
    });

    public static Stream<Arguments> GetAllCHSchemeCurve() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
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

    private void testFunction(CHConfig schemeConfig) {
        if (schemeConfig.schemeName.has_label) testLabelCH(schemeConfig);
        else if (schemeConfig.schemeName.has_ET) testCHET(schemeConfig);
        else testBaseCH(schemeConfig);
    }

    private void testBaseCH(CHConfig schemeConfig) {
        BaseCH scheme = BaseCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);
        PublicKey pk1 = pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(pk1, sk1, pp);

        PublicKey pk2 = pp.createPublicKey();
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(pk2, sk2, pp);

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");

        HashValue h1 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();
        scheme.Hash(h1, r1, pp, pk1, m1);

        HashValue h2 = pp.createHashValue();
        Randomness r2 = pp.createRandomness();
        scheme.Hash(h2, r2, pp, pk2, m2);

        assertTrue(scheme.Verify(pp, pk1, m1, h1, r1));
//        assertFalse(scheme.Verify(pp, pk2, m1, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m2, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m1, h2, r1));
        assertFalse(scheme.Verify(pp, pk1, m1, h1, r2));

        assertTrue(scheme.Verify(pp, pk2, m2, h2, r2));
//        assertFalse(scheme.Verify(pp, pk1, m2, h2, r2));
//        assertFalse(scheme.Verify(pp, pk2, m1, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, h1, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, h2, r1));

        Randomness r1_p = pp.createRandomness();

        scheme.Collision(r1_p, pp, pk1, sk1, m1, h1, r1, m2);
        assertTrue(scheme.Verify(pp, pk1, m1, h1, r1), "Adapt(L1, m2) valid");
        assertTrue(scheme.Verify(pp, pk1, m2, h1, r1_p), "Adapt(L1, m2) valid");
        assertFalse(scheme.Verify(pp, pk1, m1, h1, r1_p), "Adapt(L1, m1) invalid");
    }

    private void testCHET(CHConfig schemeConfig) {
        CHET scheme = CHETFactory.createScheme(schemeConfig);
        ChameleonHash.CH.CHET.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);
        PublicKey pk1 = pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(pk1, sk1, pp);

        PublicKey pk2 = pp.createPublicKey();
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(pk2, sk2, pp);

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");

        HashValue h1 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();
        ETrapdoor etd1 = pp.createETrapdoor();
        scheme.Hash(h1, r1, pp, pk1, m1, etd1);

        HashValue h2 = pp.createHashValue();
        Randomness r2 = pp.createRandomness();
        ETrapdoor etd2 = pp.createETrapdoor();
        scheme.Hash(h2, r2, pp, pk2, m2, etd2);

        assertTrue(scheme.Verify(pp, pk1, m1, h1, r1));
//        assertFalse(scheme.Verify(pp, pk1, m2, h1, r1));
//        assertFalse(scheme.Verify(pp, pk1, m1, h2, r1));
//        assertFalse(scheme.Verify(pp, pk1, m1, h1, r2));

        assertTrue(scheme.Verify(pp, pk2, m2, h2, r2));
//        assertFalse(scheme.Verify(pp, pk2, m2, h1, r2));
//        assertFalse(scheme.Verify(pp, pk2, m2, h2, r1));

        Randomness r1_p = pp.createRandomness();

        scheme.Collision(r1_p, pp, pk1, sk1, m1, etd1, h1, r1, m2);
        assertTrue(scheme.Verify(pp, pk1, m1, h1, r1), "Adapt(L1, m2) valid");
        assertTrue(scheme.Verify(pp, pk1, m2, h1, r1_p), "Adapt(L1, m2) valid");
        assertFalse(scheme.Verify(pp, pk1, m1, h1, r1_p), "Adapt(L1, m1) invalid");
    }

    private void testLabelCH(CHConfig schemeConfig) {
        LabelCH scheme = LabelCHFactory.createScheme(schemeConfig);
        ChameleonHash.CH.LabelCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);
        PublicKey pk1 = pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(pk1, sk1, pp);

        PublicKey pk2 = pp.createPublicKey();
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(pk2, sk2, pp);

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");

        ChameleonHash.CH.LabelCH.Components.Label l1 = pp.createLabel("label1");
        ChameleonHash.CH.LabelCH.Components.Label l2 = pp.createLabel("label2");

        HashValue h1 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();
        scheme.Hash(h1, r1, pp, pk1, m1, l1);

        HashValue h2 = pp.createHashValue();
        Randomness r2 = pp.createRandomness();
        scheme.Hash(h2, r2, pp, pk2, m2, l2);

        assertTrue(scheme.Verify(pp, pk1, m1, l1, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m2, l1, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m1, l2, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m1, l1, h2, r1));
        assertFalse(scheme.Verify(pp, pk1, m1, l1, h1, r2));

        assertTrue(scheme.Verify(pp, pk2, m2, l2, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m1, l2, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, l1, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, l2, h1, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, l2, h2, r1));

        Randomness r1_p = pp.createRandomness();

        scheme.Collision(r1_p, pp, pk1, sk1, m1, l1, h1, r1, m2);
        assertTrue(scheme.Verify(pp, pk1, m1, l1, h1, r1), "Adapt(L1, m2) valid");
        assertTrue(scheme.Verify(pp, pk1, m2, l1, h1, r1_p), "Adapt(L1, m2) valid");
        assertFalse(scheme.Verify(pp, pk1, m1, l1, h1, r1_p), "Adapt(L1, m1) invalid");
    }

    @DisplayName("test abstract implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.CHTest#GetAllCHSchemeCurve")
    void CHDSTest(CHName schemeName, CurveName curveName) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        Config curveConfig = new Config(curveName, curve_param);
        CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }

    @DisplayName("test swap G1 and G2 implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.CHTest#GetAllCHSchemeASCurve")
    void CHSGGTest(CHName schemeName, CurveName curveName) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", true);
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        Config curveConfig = new Config(curveName, curve_param);
        CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }

    @DisplayName("test single group scheme")
    @ParameterizedTest(name = "test scheme {0} curve {1} group {2}")
    @MethodSource("UnitTest.CHScheme.CHTest#GetAllCHSchemeSingleGroup")
    void CHSingleGroupTest(CHName schemeName, CurveName curveName, CurveGroup curveGroup) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        params.put("curve_group", curveGroup);
        params.put("nizk_config", new NIZKConfig(NIZKName.DL));
        params.put("pke_config", new PKEConfig(PKEName.RSA));
        Config curveConfig = new Config(curveName, curve_param);
        CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
        CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
        params.put("ch_config", BC_CH);
        testFunction(schemeConfig);
    }
}
