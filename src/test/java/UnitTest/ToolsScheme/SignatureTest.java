package UnitTest.ToolsScheme;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveName;
import Signature.Components.*;
import Signature.S;
import Signature.SFactory;
import Signature.SName;
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

public class SignatureTest {
    static List<SName> skipList = List.of(new SName[]{
            SName.BLS,
//            IBCH_ZSS_2003_S2,
    });

    public static Stream<Arguments> GetSignSchemeCurveProduct() {
        return EnumSet.allOf(SName.class).stream().flatMap(
                a -> EnumSet.allOf(CurveName.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b)))
        );
    }

    @DisplayName("test signature scheme")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.ToolsScheme.SignatureTest#GetSignSchemeCurveProduct")
    void STest(SName sName, CurveName curveName) {
        if (skipList.contains(sName)) {
            System.out.println("跳过测试：方案 " + sName);
            return;
        }
        if (!sName.checkCurve(curveName)) {
            System.out.println("跳过测试：方案 " + sName + " 不支持曲线 " + curveName);
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
        Config curveConfig = new Config(curveName, curve_param);
        Signature.Config schemeConfig = new Signature.Config(sName, curveConfig, params);
        S scheme = SFactory.createS(schemeConfig);
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
        SignValue s1 = pp.createSignValue();
        SignValue s2 = pp.createSignValue();

        scheme.Sign(s1, pp, sk1, m1);
        scheme.Sign(s2, pp, sk2, m2);

        assertFalse(s1.isEqual(s2), "s1 != s2");

        assertTrue(scheme.Verify(pp, pk1, s1, m1), "valid sign(m1)");
        assertTrue(scheme.Verify(pp, pk2, s2, m2), "valid sign(m2)");

        assertFalse(scheme.Verify(pp, pk1, s2, m1), "sign(m1) != s2");
        assertFalse(scheme.Verify(pp, pk2, s1, m1), "sign(pk2, m1) != s1");
    }
}
