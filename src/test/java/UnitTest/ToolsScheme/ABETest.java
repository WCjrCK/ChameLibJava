package UnitTest.ToolsScheme;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveName;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.ABE.BaseABE.Components.Attributes;
import Encryption.ABE.BaseABE.FAME.*;
import Encryption.ABE.Interface.RevocableABE;
import Encryption.ABE.RevocableABE.Components.Authority;
import Encryption.ABE.RevocableABE.Components.Info;
import Encryption.ABE.RevocableABE.Components.User;
import Encryption.ABE.RevocableABE.RevocableABEFactory;
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

    public static Stream<Arguments> GetAllRABECurveSwapTag() {
        return EnumSet.allOf(CurveName.class).stream()
                .filter(a -> a != SECP256K1)
                .filter(a -> a != PBC_CUSTOM)
                .flatMap(
                        a -> Stream.of(false, true)
                                .filter(b -> !(b && a.isSymmetic()))
                                .flatMap(b -> EnumSet.allOf(ABEName.class).stream()
                                        .filter(c -> c.revokable)
                                        .flatMap(
                                                c -> Stream.of(Arguments.of(c, a, b))
                                        )
                                )
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
        ABEConfig schemeConfig = new ABEConfig(ABEName.ABE_FAME, curveConfig, params);

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

    @DisplayName("test RABE")
    @ParameterizedTest(name = "test scheme {0} curve {1} swap_G1G2 {2}")
    @MethodSource("UnitTest.ToolsScheme.ABETest#GetAllRABECurveSwapTag")
    void RABE(ABEName abeName, CurveName curve, boolean swap_G1G2) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", swap_G1G2);
//        if (curveName == PBC_CUSTOM) {
//            curve_param.put("param_file_path", "./jpbc/params/a.properties");
//            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
//        }
        Config curveConfig = new Config(curve, curve_param);

        params.put("max_user", 1024);

        ABEConfig schemeConfig = new ABEConfig(abeName, curveConfig, params);
        {
            RevocableABE scheme = RevocableABEFactory.createRevocableABE(schemeConfig);
            Encryption.ABE.RevocableABE.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            Encryption.ABE.RevocableABE.Components.MasterPublicKey mpk = pp.createMasterPublicKey();
            Authority Auth = pp.createAuthority();
            Auth.Setup(mpk, pp);

            User u1 = pp.createUser("user1");
            u1.S.addAttr("A");
            u1.S.addAttr("DDDD");

            User u2 = pp.createUser("user2");
            u2.S.addAttr("BB");
            u2.S.addAttr("CCC");

            User u3 = pp.createUser("user3");
            u3.S.addAttr("A");
            u3.S.addAttr("BB");
            u3.S.addAttr("CCC");

            Auth.KeyGen(u1, pp, mpk);
            Auth.KeyGen(u2, pp, mpk);
            Auth.KeyGen(u3, pp, mpk);

            Encryption.ABE.RevocableABE.Components.PlainText pt1 = pp.createPlainText("msg1");
            Encryption.ABE.RevocableABE.Components.PlainText pt2 = pp.createPlainText("msg2");
            Encryption.ABE.RevocableABE.Components.PlainText pt3 = pp.createPlainText("msg3");

            Encryption.ABE.RevocableABE.Components.CipherText ct1 = pp.createCipherText();
            Encryption.ABE.RevocableABE.Components.CipherText ct2 = pp.createCipherText();

            Encryption.ABE.RevocableABE.Components.Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");

            Info i = pp.createInfo();
            i.setValue(new HashMap<>(){{put("timestamp", 5);}});
            u1.Encrypt(ct1, pp, mpk, P, pt1, i);

            Auth.KeyUpdate(pp, mpk, i);

            Auth.DecryptKeyGen(u1, pp, mpk);
            Auth.DecryptKeyGen(u2, pp, mpk);
            Auth.DecryptKeyGen(u3, pp, mpk);

            u1.Decrypt(pt3, pp, mpk, P, ct1);
            assertTrue(pt3.isEqual(pt1), "decrypt(dk_1_1, ct1) == m1");

            u2.Decrypt(pt3, pp, mpk, P, ct1);
            assertFalse(pt3.isEqual(pt1), "policy false");

            u3.Decrypt(pt3, pp, mpk, P, ct1);
            assertTrue(pt3.isEqual(pt1), "decrypt(dk_3_1, ct1) == m1");


            i.setValue(new HashMap<>(){{put("timestamp", 10);}});
            Auth.Revoke(pp, mpk, u1, i);

            i.setValue(new HashMap<>(){{put("timestamp", 50);}});
            u2.Encrypt(ct2, pp, mpk, P, pt2, i);

            Auth.KeyUpdate(pp, mpk, i);

            Auth.DecryptKeyGen(u1, pp, mpk);
            Auth.DecryptKeyGen(u2, pp, mpk);
            Auth.DecryptKeyGen(u3, pp, mpk);

            u1.Decrypt(pt3, pp, mpk, P, ct2);
            assertFalse(pt3.isEqual(pt2), "banned id1");

            u2.Decrypt(pt3, pp, mpk, P, ct2);
            assertFalse(pt3.isEqual(pt2), "policy false");

            u3.Decrypt(pt3, pp, mpk, P, ct2);
            assertTrue(pt3.isEqual(pt2), "decrypt(dk_3_1, ct1) == m1");


            i.setValue(new HashMap<>(){{put("timestamp", 100);}});
            Auth.Revoke(pp, mpk, u2, i);

            Auth.KeyUpdate(pp, mpk, i);

            Auth.DecryptKeyGen(u1, pp, mpk);
            Auth.DecryptKeyGen(u2, pp, mpk);
            Auth.DecryptKeyGen(u3, pp, mpk);

            u1.Decrypt(pt3, pp, mpk, P, ct2);
            assertFalse(pt3.isEqual(pt2), "different time");

            u2.Decrypt(pt3, pp, mpk, P, ct2);
            assertFalse(pt3.isEqual(pt2), "different time");

            u3.Decrypt(pt3, pp, mpk, P, ct2);
            assertFalse(pt3.isEqual(pt2), "different time");
        }
    }
}
