package UnitTest.CHScheme;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
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

public class PBCHTest {
    public static Stream<Arguments> GetAllPBCHSchemeCurve() {
        return EnumSet.allOf(PBCHName.class).stream()
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

    private void testFunction(PBCHConfig schemeConfig) {
//        if (schemeConfig.schemeName.has_label) testLabelCH(schemeConfig);
//        else if (schemeConfig.schemeName.has_ET) testCHET(schemeConfig);
//        else testBaseCH(schemeConfig);
        testBasePBCH(schemeConfig);
    }

    private void testBasePBCH(PBCHConfig schemeConfig) {
        BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();

        scheme.Setup(pp, mpk, msk);

        Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");

        Attributes S1 = pp.createAttributes();
        Attributes S2 = pp.createAttributes();

        S1.addAttr("A");
        S1.addAttr("DDDD");

        S2.addAttr("BB");
        S2.addAttr("CCC");

        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(sk1, pp, mpk, msk, S1);
        SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(sk2, pp, mpk, msk, S2);

        HashValue h1 = pp.createHashValue();
        HashValue h2 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();
        Randomness r2 = pp.createRandomness();
        Randomness r_p = pp.createRandomness();

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");

        scheme.Hash(h1, r1, pp, mpk, m1, P);

        assertTrue(scheme.Verify(pp, mpk, m1, h1, r1), "H(m1) valid");
        assertFalse(scheme.Verify(pp, mpk, m2, h1, r1), "H(m2) invalid");

        scheme.Hash(h2, r2, pp, mpk, m2, P);
        assertTrue(scheme.Verify(pp, mpk, m2, h2, r2), "H(m2) valid");
        assertFalse(scheme.Verify(pp, mpk, m1, h2, r2), "H(m1) invalid");

        scheme.Collision(r_p, pp, mpk, sk1, m1, P, h1, r1, m2);
        assertTrue(scheme.Verify(pp, mpk, m2, h1, r_p), "Adapt(m2) valid");
        assertFalse(scheme.Verify(pp, mpk, m1, h1, r_p), "Adapt(m1) invalid");
    }

    static List<PBCHName> skipList = List.of(new PBCHName[]{
    });

    @DisplayName("test abstract implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.PBCHTest#GetAllPBCHSchemeCurve")
    void CHDSTest(PBCHName schemeName, CurveName curveName) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        Config curveConfig = new Config(curveName, curve_param);
        Map<String, Object> chetParam = new HashMap<>();
        Map<String, Object> chParam = new HashMap<>();
        chParam.put("curve_group", CurveGroup.G1);
        chetParam.put("ch_config", new CHConfig(CHName.DSS_2020, curveConfig, chParam));
        params.put("chet_config", new CHConfig(CHName.BC_CDK_2017, curveConfig, chetParam));
        Map<String, Object> seParam = new HashMap<>();
        seParam.put("algorithm", "AES");
        seParam.put("transformation", "AES/ECB/PKCS5Padding");
        params.put("se_config", new SEConfig(SEName.AES, seParam));

        PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }
}
