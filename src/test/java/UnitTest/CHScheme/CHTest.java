package UnitTest.CHScheme;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.Components.*;
import ChameleonHash.SchemeCurveRequire;
import ChameleonHash.SchemeFactory;
import ChameleonHash.SchemeName;
import ChameleonHash.SchemeType;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
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
    static List<SchemeName> skipList = List.of(new SchemeName[]{
//            IBCH_ZSS_2003_S1,
//            IBCH_ZSS_2003_S2,
//            IBCH_CZS_2014,
//            IBCH_LSX_2022,
//            IBCH_XSL_2021,
//            IBCH_LJF_2025,
    });

    public static Stream<Arguments> GetAllCHSchemeCurve() {
        return EnumSet.allOf(SchemeName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeType == SchemeType.CH)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> b != SECP256K1)
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllCHSchemeASCurve() {
        return EnumSet.allOf(SchemeName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeType == SchemeType.CH)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> b != SECP256K1)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    public static Stream<Arguments> GetAllCHSchemeSingleGroup() {
        return EnumSet.allOf(SchemeName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeType == SchemeType.CH)
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                        .filter(b -> b != SECP256K1)
                        .filter(a::checkCurve)
                        .flatMap(
                                b -> EnumSet.allOf(CurveGroup.class).stream()
                                .filter(c -> c != CurveGroup.Zp)
                                .flatMap(c -> Stream.of(Arguments.of(a, b, c)))
                        )
                );
    }

    private void testFunction(ChameleonHash.Config schemeConfig) {
        CH scheme = (CH) SchemeFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);
        PublicKey pk1 = (PublicKey) pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(pk1, sk1, pp);

        PublicKey pk2 = (PublicKey) pp.createPublicKey();
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
        assertFalse(scheme.Verify(pp, pk2, m1, h1, r1));
        assertFalse(scheme.Verify(pp, pk1, m2, h1, r1));

        assertTrue(scheme.Verify(pp, pk2, m2, h2, r2));
        assertFalse(scheme.Verify(pp, pk1, m2, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m1, h2, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, h1, r2));
        assertFalse(scheme.Verify(pp, pk2, m2, h2, r1));

        Randomness r1_p = pp.createRandomness();

        scheme.Collision(r1_p, pp, pk1, sk1, m1, h1, r1, m2);
        assertTrue(scheme.Verify(pp, pk1, m1, h1, r1), "Adapt(L1, m2) valid");
        assertTrue(scheme.Verify(pp, pk1, m2, h1, r1_p), "Adapt(L1, m2) valid");
        assertFalse(scheme.Verify(pp, pk1, m1, h1, r1_p), "Adapt(L1, m1) invalid");
    }

    @DisplayName("test abstract implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.IBCHTest#GetAllIBCHSchemeCurve")
    void CHDSTest(SchemeName schemeName, CurveName curveName) {
        if (skipList.contains(schemeName)) {
            System.out.println("跳过测试：方案 " + schemeName);
            return;
        }
        if (!schemeName.checkCurve(curveName)) {
            System.out.println("跳过测试：方案 " + schemeName + " 不支持曲线 " + curveName);
            return;
        }
        if (curveName == SECP256K1) {
            System.out.println("MCL 库未正确实现该曲线，跳过测试");
            return;
        }
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        params.put("ID_Binary_Len", 64);
        Config curveConfig = new Config(curveName, curve_param);
        ChameleonHash.Config schemeConfig = new ChameleonHash.Config(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }

    @DisplayName("test swap G1 and G2 implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.CHTest#GetAllCHSchemeCurve")
    void CHSGGTest(SchemeName schemeName, CurveName curveName) {
        if (skipList.contains(schemeName)) {
            System.out.println("跳过测试：方案 " + schemeName);
            return;
        }
        if (!schemeName.checkCurve(curveName)) {
            System.out.println("跳过测试：方案 " + schemeName + " 不支持曲线 " + curveName);
            return;
        }
        if (curveName.isSymmetic()) {
            System.out.println("对称曲线无需测试交换");
            return;
        }
        if (curveName == SECP256K1) {
            System.out.println("MCL 库未正确实现该曲线，跳过测试");
            return;
        }
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", true);
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        params.put("ID_Binary_Len", 64);
        Config curveConfig = new Config(curveName, curve_param);
        ChameleonHash.Config schemeConfig = new ChameleonHash.Config(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }

    @DisplayName("test single group scheme")
    @ParameterizedTest(name = "test scheme {0} curve {1} group {2}")
    @MethodSource("UnitTest.CHScheme.CHTest#GetAllCHSchemeSingleGroup")
    void CHSingleGroupTest(SchemeName schemeName, CurveName curveName, CurveGroup curveGroup) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", true);
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        params.put("curve_group", curveGroup);
        Config curveConfig = new Config(curveName, curve_param);
        ChameleonHash.Config schemeConfig = new ChameleonHash.Config(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }
}
