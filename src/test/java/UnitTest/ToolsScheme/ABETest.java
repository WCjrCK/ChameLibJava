package UnitTest.ToolsScheme;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveName;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.BaseABE.FAME.*;
import Encryption.ABE.Components.Attributes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.PBC_CUSTOM;
import static EllipticCurve.Curve.CurveName.SECP256K1;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ABETest {
    public static Stream<Arguments> GetAllCurveSwapTag() {
        return EnumSet.allOf(CurveName.class).stream()
                .filter(a -> a != SECP256K1)
                .filter(a -> a != PBC_CUSTOM)
                .flatMap(
                        a -> Stream.of(false, true)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    @DisplayName("test ABE")
    @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
    @MethodSource("UnitTest.ToolsScheme.ABETest#GetAllCurveSwapTag")
    void ABE(CurveName curve, boolean swap_G1G2) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", swap_G1G2);
//        if (curveName == PBC_CUSTOM) {
//            curve_param.put("param_file_path", "./jpbc/params/a.properties");
//            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
//        }
        Config curveConfig = new Config(curve, curve_param);
        ABEConfig schemeConfig = new ABEConfig(ABEName.FAME, curveConfig, params);

        Scheme scheme = new Scheme();
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(mpk, msk, pp);

        Policy p = pp.createPolicy("((A1|(A2|A3))&(DDDD|(BB&CCC)))&(((T1&T2)|(T2&T3))|(T1&T3))");

//        for (int i = 0;i < p.MSP.M.length; ++i) System.out.println(Arrays.toString(p.MSP.M[i]));

        Attributes S1 = pp.createAttributes();
        Attributes S2 = pp.createAttributes();

        S1.addAttr("A1");
        S1.addAttr("DDDD");
        S1.addAttr("T2");
        S1.addAttr("T3");

        S2.addAttr("BB");
        S2.addAttr("CCC");
        S2.addAttr("T1");
        S2.addAttr("T3");

        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(sk1, pp, mpk, msk, S1);
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(sk2, pp, mpk, msk, S2);

        PlainText m1 = pp.createPlainText("msg1");
        PlainText m2 = pp.createPlainText("msg2");
        PlainText m3 = pp.createPlainText("msg3");

        CipherText ct1 = pp.createCipherText();
        CipherText ct2 = pp.createCipherText();

        scheme.Encrypt(ct1, pp, mpk, p, m1);
        scheme.Decrypt(m3, pp, mpk, sk1, ct1, p);
        assertTrue(m3.isEqual(m1), "decrypt(sk1, ct1) != m1");

        scheme.Encrypt(ct2, pp, mpk, p, m2);
        scheme.Decrypt(m3, pp, mpk, sk1, ct2, p);
        assertTrue(m3.isEqual(m2), "decrypt(sk1, ct2) != m2");

        scheme.Decrypt(m3, pp, mpk, sk2, ct1, p);
        assertFalse(m3.isEqual(m1), "decrypt(sk2, ct1) invalid");
        assertFalse(m3.isEqual(m2), "decrypt(sk2, ct1) invalid");
    }
}
