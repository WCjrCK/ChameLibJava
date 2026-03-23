package UnitTest.CHScheme;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.Interface.RevocablePBCH;
import ChameleonHash.PBCH.BAPBCH.BAPBCHFactory;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.PBCH.RevocablePBCH.RevocablePBCHFactory;
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
import static org.junit.jupiter.api.Assertions.*;

public class PBCHTest {
    static List<PBCHName> skipList = List.of(new PBCHName[]{
            PBCHName.DSS_2019,
            PBCHName.TLL_2020,
            PBCHName.XNM_2021,
//            PBCHName.TMM_2022,
    });

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

    public static Stream<Arguments> GetAllPBCHSchemeASCurve() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(
                        a -> EnumSet.allOf(CurveName.class).stream()
                                .filter(b -> b != SECP256K1)
                                .filter(b -> b != PBC_CUSTOM)
                                .filter(b -> !b.isSymmetic())
                                .filter(a::checkCurve)
                                .flatMap(b -> Stream.of(Arguments.of(a, b)))
                );
    }

    private void testFunction(PBCHConfig schemeConfig) {
        if (schemeConfig.schemeName.has_blackbox_accountability) testBAPBCH(schemeConfig);
        else if (schemeConfig.schemeName.revocable) testRPBCH(schemeConfig);
        else testBasePBCH(schemeConfig);
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

        scheme.Collision(r_p, pp, mpk, sk1, m1, h1, r1, m2);
        assertTrue(scheme.Verify(pp, mpk, m2, h1, r_p), "Adapt(m2) valid");
        assertFalse(scheme.Verify(pp, mpk, m1, h1, r_p), "Adapt(m1) invalid");
    }

    private void testBAPBCH(PBCHConfig schemeConfig) {
        BAPBCH scheme = BAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.BAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        MasterPublicKey mpk = pp.createMasterPublicKey();
        MasterSecretKey msk = pp.createMasterSecretKey();

        scheme.Setup(pp, mpk, msk);

        Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");

        User u1 = pp.createUser(((int) schemeConfig.params.get("id_len")) / 3);
        scheme.AssignUser(u1, pp, mpk, msk);
        u1.S.addAttr("A");
        u1.S.addAttr("DDDD");
        scheme.KeyGen(u1, pp, mpk, msk);

        User u2 = pp.createUser(u1, ((int) schemeConfig.params.get("id_len")) / 2);
        scheme.AssignUser(u2, pp, mpk, msk);
        u2.S.addAttr("BB");
        u2.S.addAttr("CCC");
        scheme.KeyGen(u2, pp, mpk, msk);

        HashValue h1 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");

        scheme.Hash(h1, r1, pp, mpk, u1, m1, P);
        assertTrue(scheme.Verify(pp, mpk, m1, h1, r1), "H(m1) valid");
        assertFalse(scheme.Verify(pp, mpk, m2, h1, r1), "H(m2) invalid");

        HashValue h2 = pp.createHashValue();
        Randomness r2 = pp.createRandomness();

        scheme.Hash(h2, r2, pp, mpk, u2, m2, P);
        assertTrue(scheme.Verify(pp, mpk, m2, h2, r2), "H(m2) valid");
        assertFalse(scheme.Verify(pp, mpk, m1, h2, r2), "H(m1) invalid");
        assertFalse(scheme.Verify(pp, mpk, m2, h1, r2), "H(m1) invalid");
        assertFalse(scheme.Verify(pp, mpk, m2, h2, r1), "H(m1) invalid");

        Randomness r_p = pp.createRandomness();

        scheme.Collision(r_p, pp, mpk, msk, u1, m1, P, h1, r1, m2);
        assertTrue(scheme.Verify(pp, mpk, m2, h1, r_p), "Adapt(m2) valid");
        assertFalse(scheme.Verify(pp, mpk, m1, h1, r_p), "Adapt(m1) invalid");

        scheme.Collision(r_p, pp, mpk, msk, u1, m2, P, h2, r2, m1);
        assertTrue(scheme.Verify(pp, mpk, m1, h2, r_p), "Adapt(m1) valid");
        assertFalse(scheme.Verify(pp, mpk, m2, h2, r_p), "Adapt(m2) invalid");
//
//        scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
//        assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
//        assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");
//
//        scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
//        assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
//        assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");
//
//        scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u2, MSP, m2, m1);
//        assertFalse(scheme.Check(h2, r1_p, SP, mpk, m1), "policy false");
//        assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "policy false");
//
//        scheme.Hash(h1, r1, pp, mpk, m1, P);
//
//        assertTrue(scheme.Verify(pp, mpk, m1, h1, r1), "H(m1) valid");
//        assertFalse(scheme.Verify(pp, mpk, m2, h1, r1), "H(m2) invalid");
//
//        scheme.Hash(h2, r2, pp, mpk, m2, P);
//        assertTrue(scheme.Verify(pp, mpk, m2, h2, r2), "H(m2) valid");
//        assertFalse(scheme.Verify(pp, mpk, m1, h2, r2), "H(m1) invalid");
//
//        scheme.Collision(r_p, pp, mpk, sk1, m1, P, h1, r1, m2);
//        assertTrue(scheme.Verify(pp, mpk, m2, h1, r_p), "Adapt(m2) valid");
//        assertFalse(scheme.Verify(pp, mpk, m1, h1, r_p), "Adapt(m1) invalid");
    }

    private void testRPBCH(PBCHConfig schemeConfig) {
        RevocablePBCH scheme = RevocablePBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey mpk = pp.createMasterPublicKey();

        ChameleonHash.PBCH.RevocablePBCH.Components.Authority Auth = pp.createAuthority();
        Auth.Setup(mpk, pp);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u1 = pp.createUser("u1");
        u1.S.addAttr("A");
        u1.S.addAttr("DDDD");
        Auth.KeyGen(u1, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u2 = pp.createUser("u2");
        u2.S.addAttr("BB");
        u2.S.addAttr("CCC");
        Auth.KeyGen(u2, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u3 = pp.createUser("u3");
        u3.S.addAttr("A");
        u3.S.addAttr("BB");
        u3.S.addAttr("CCC");
        Auth.KeyGen(u3, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.Message m1 = pp.createMessage("msg1");
        ChameleonHash.PBCH.RevocablePBCH.Components.Message m2 = pp.createMessage("msg2");
        ChameleonHash.PBCH.RevocablePBCH.Components.Message m3 = pp.createMessage("msg3");

        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h1 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h2 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h3 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r1 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r2 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r3 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r_p = pp.createRandomness();

        ChameleonHash.PBCH.RevocablePBCH.Components.Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");

        ChameleonHash.PBCH.RevocablePBCH.Components.Info i = pp.createInfo();
        i.setValue(new HashMap<>(){{put("timestamp", 5);}});

        u1.Hash(h1, r1, pp, mpk, m1, P, i);

        assertTrue(u1.Verify(pp, mpk, m1, h1, r1), "H(m1) valid");
        assertFalse(u1.Verify(pp, mpk, m2, h1, r1), "H(m2) invalid");
        assertFalse(u1.Verify(pp, mpk, m3, h1, r1), "H(m3) invalid");

        Auth.KeyUpdate(pp, mpk, i);

        Auth.DecryptKeyGen(u1, pp, mpk);
        Auth.DecryptKeyGen(u2, pp, mpk);
        Auth.DecryptKeyGen(u3, pp, mpk);

        u1.Collision(r_p, pp, mpk, m1, h1, r1, m2);
        assertTrue(u1.Verify(pp, mpk, m2, h1, r_p));
        assertFalse(u1.Verify(pp, mpk, m1, h1, r_p));

        assertThrowsExactly(RuntimeException.class, () -> {
            u2.Collision(r_p, pp, mpk, m1, h1, r1, m2);
            if(!u2.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });

        if (schemeConfig.schemeName != PBCHName.TMM_2022) {
            u3.Collision(r_p, pp, mpk, m1, h1, r1, m2);
            assertTrue(u3.Verify(pp, mpk, m2, h1, r_p));
            assertFalse(u3.Verify(pp, mpk, m1, h1, r_p));
        }

        i.setValue(new HashMap<>(){{put("timestamp", 10);}});

        Auth.Revoke(pp, mpk, u1, i);

        i.setValue(new HashMap<>(){{put("timestamp", 50);}});

        u2.Hash(h2, r2, pp, mpk, m1, P, i);

        Auth.KeyUpdate(pp, mpk, i);

        Auth.DecryptKeyGen(u1, pp, mpk);
        Auth.DecryptKeyGen(u2, pp, mpk);
        Auth.DecryptKeyGen(u3, pp, mpk);

        assertThrowsExactly(RuntimeException.class, () -> {
            u1.Collision(r_p, pp, mpk, m2, h2, r2, m2);
            if(!u1.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });

        assertThrowsExactly(RuntimeException.class, () -> {
            u2.Collision(r_p, pp, mpk, m2, h2, r2, m2);
            if(!u2.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });

        if (schemeConfig.schemeName != PBCHName.TMM_2022) {
            u3.Collision(r_p, pp, mpk, m1, h2, r2, m2);
            assertTrue(u3.Verify(pp, mpk, m2, h2, r_p));
            assertFalse(u3.Verify(pp, mpk, m1, h2, r_p));
        }

        i.setValue(new HashMap<>(){{put("timestamp", 100);}});
        Auth.Revoke(pp, mpk, u2, i);

        Auth.KeyUpdate(pp, mpk, i);

        Auth.DecryptKeyGen(u1, pp, mpk);
        Auth.DecryptKeyGen(u2, pp, mpk);
        Auth.DecryptKeyGen(u3, pp, mpk);

        assertThrowsExactly(RuntimeException.class, () -> {
            u1.Collision(r_p, pp, mpk, m2, h2, r2, m2);
            if(!u1.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });

        assertThrowsExactly(RuntimeException.class, () -> {
            u2.Collision(r_p, pp, mpk, m2, h2, r2, m2);
            if(!u2.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });

        assertThrowsExactly(RuntimeException.class, () -> {
            u3.Collision(r_p, pp, mpk, m2, h2, r2, m2);
            if(!u3.Verify(pp, mpk, m2, h1, r_p)) throw new RuntimeException();
        });
    }

    @DisplayName("test abstract implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.PBCHTest#GetAllPBCHSchemeCurve")
    void PBCHDSTest(PBCHName schemeName, CurveName curveName) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
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
        params.put("id_len", 32);
        params.put("max_user", 2048);
        params.put("curve_group", CurveGroup.G1);

        PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }

    @DisplayName("test swap G1 and G2 implement")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("UnitTest.CHScheme.PBCHTest#GetAllPBCHSchemeASCurve")
    void PBCHSGGTest(PBCHName schemeName, CurveName curveName) {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        curve_param.put("swap_G1G2", true);
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
        params.put("id_len", 32);
        params.put("max_user", 2048);
        params.put("curve_group", CurveGroup.G1);

        PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);
        testFunction(schemeConfig);
    }
}
