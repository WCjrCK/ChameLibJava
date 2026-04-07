package UnitTest.CHScheme;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.BaseCH.Components.*;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.IBCH.IBCHName;
import ChameleonHash.Interface.*;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.MAPBCH.MAPBCHFactory;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.PBCH.RevocablePBCH.RevocablePBCHFactory;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.ABEName;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEName;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Print selected scheme components")
public class SchemeComponentOutputTest {
    private static final CurveName CURVE_NAME = CurveName.BN254;
    private static final int XSL_ID_BINARY_LEN = 32;
    private static final String DEFAULT_POLICY = "A&(DDDD|(BB&CCC))";
    private static final int MAX_DUMP_DEPTH = 8;
    private static final int MAX_CONTAINER_PREVIEW = 4;
    private static final int CONTAINER_HEAD_PREVIEW = 2;
    private static final int CONTAINER_TAIL_PREVIEW = 1;
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();
    private static final Set<String> SKIPPED_FIELD_NAMES = Set.of(
            "curve",
            "curveConfig",
            "core",
            "scheme",
            "CHScheme",
            "CHETScheme",
            "CHET",
            "SEScheme",
            "SE",
            "FAME",
            "MAABE",
            "RABE",
            "rand"
    );

    @Test
    @DisplayName("Print CCT_2024 components")
    void printCCT2024Components() {
        CHConfig schemeConfig = buildCCT2024Config();
        printSchemeHeader("CCT+24", schemeConfig.curveConfig.curveName.name());

        BaseCH scheme = BaseCHFactory.createScheme(schemeConfig);
        PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);
        printStage("Setup");
        printComponent("公共参数", pp);

        PublicKey pk1 = pp.createPublicKey();
        SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(pk1, sk1, pp);

        printStage("KeyGen");
        printComponent("公钥", pk1);
        printComponent("私钥", sk1);

        Message m1 = pp.createMessage("msg1");
        Message m2 = pp.createMessage("msg2");
//        printStage("Messages");

        HashValue h1 = pp.createHashValue();
        Randomness r1 = pp.createRandomness();
        scheme.Hash(h1, r1, pp, pk1, m1);

        printStage("Hash");
        printComponent("消息1（嵌入前为\"msg1\"）", m1);
        printComponent("哈希值（对应消息\"msg1\"）", h1);
        printComponent("随机值（对应消息\"msg1\"）", r1);

        boolean verifyPk1M1 = scheme.Verify(pp, pk1, m1, h1, r1);
        boolean verifyPk1M2 = scheme.Verify(pp, pk1, m2, h1, r1);

        printStage("Verify");
        printCheck("校验结果", verifyPk1M1);

        assertTrue(verifyPk1M1);
        assertFalse(verifyPk1M2);

        Randomness r1Prime = pp.createRandomness();
        scheme.Collision(r1Prime, pp, pk1, sk1, m1, h1, r1, m2);

        printStage("Collision");
        printComponent("消息2（嵌入前为\"msg2\"）", m2);
        printComponent("新随机值（对应消息\"msg2\"）", r1Prime);

        boolean verifyOriginal = scheme.Verify(pp, pk1, m1, h1, r1);
        boolean verifyCollision = scheme.Verify(pp, pk1, m2, h1, r1Prime);
        boolean verifyWrongCollision = scheme.Verify(pp, pk1, m1, h1, r1Prime);

//        printCheck("Verify original pair after collision", verifyOriginal);
//        printCheck("校验结果", verifyCollision);
//        printCheck("Verify old message with collided randomness", verifyWrongCollision);

        assertTrue(verifyOriginal, "Adapt(L1, m2) valid");
        assertTrue(verifyCollision, "Adapt(L1, m2) valid");
        assertFalse(verifyWrongCollision, "Adapt(L1, m1) invalid");
    }

    @Test
    @DisplayName("Print XSL_2021 components")
    void printXSL2021Components() {
        IBCHConfig schemeConfig = buildXSL2021Config();
        printSchemeHeader("XSL+21", schemeConfig.curveConfig.curveName.name());

        BaseIBCH scheme = BaseIBCHFactory.createScheme(schemeConfig);
        ChameleonHash.IBCH.BaseIBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.IBCH.BaseIBCH.Components.MasterSecretKey msk = pp.createMasterSecretKey();
        scheme.Setup(pp, msk);

//        printStage("Setup");
//        printComponent("公共参数", pp);
//        printComponent("主私钥", msk);

        ChameleonHash.IBCH.BaseIBCH.Components.SecretKey sk1 = pp.createSecretKey();
        ChameleonHash.IBCH.BaseIBCH.Components.Identity id1 = pp.createIdentity("ID1");
        scheme.KeyGen(sk1, pp, msk, id1);

        ChameleonHash.IBCH.BaseIBCH.Components.SecretKey sk2 = pp.createSecretKey();
        ChameleonHash.IBCH.BaseIBCH.Components.Identity id2 = pp.createIdentity("ID2");
        scheme.KeyGen(sk2, pp, msk, id2);

        printStage("KeyGen");
        printComponent("身份标识（嵌入前为\"ID1\"）", id1);
        printComponent("对应私钥", sk1);
//        printComponent("id2", id2);
//        printComponent("sk2", sk2);

        ChameleonHash.IBCH.BaseIBCH.Components.Message m1 = pp.createMessage("msg1");
        ChameleonHash.IBCH.BaseIBCH.Components.Message m2 = pp.createMessage("msg2");
//        printStage("Messages");

        ChameleonHash.IBCH.BaseIBCH.Components.HashValue h1 = pp.createHashValue();
        ChameleonHash.IBCH.BaseIBCH.Components.Randomness r1 = pp.createRandomness();
        scheme.Hash(h1, r1, pp, id1, m1);

        ChameleonHash.IBCH.BaseIBCH.Components.HashValue h2 = pp.createHashValue();
        ChameleonHash.IBCH.BaseIBCH.Components.Randomness r2 = pp.createRandomness();
        scheme.Hash(h2, r2, pp, id2, m2);

        printStage("Hash");
        printComponent("消息1（嵌入前为\"msg1\"）", m1);
        printComponent("哈希值（对应消息\"msg1\"）", h1);
        printComponent("随机值（对应消息\"msg1\"）", r1);
//        printComponent("h2", h2);
//        printComponent("r2", r2);

        boolean verifyId1M1 = scheme.Verify(pp, id1, m1, h1, r1);
        boolean verifyId2M1 = scheme.Verify(pp, id2, m1, h1, r1);
        boolean verifyId1M2 = scheme.Verify(pp, id1, m2, h1, r1);
        boolean verifyId2M2 = scheme.Verify(pp, id2, m2, h2, r2);
        boolean verifyId1H2 = scheme.Verify(pp, id1, m2, h2, r2);
        boolean verifyId2M1H2 = scheme.Verify(pp, id2, m1, h2, r2);
        boolean verifyId2H1 = scheme.Verify(pp, id2, m2, h1, r2);
        boolean verifyId2R1 = scheme.Verify(pp, id2, m2, h2, r1);

        printStage("Verify");
        printCheck("校验结果", verifyId1M1);
//        printCheck("Verify(ID1, m1, h1, r1)", verifyId1M1);
//        printCheck("Verify(ID2, m1, h1, r1)", verifyId2M1);
//        printCheck("Verify(ID1, m2, h1, r1)", verifyId1M2);
//        printCheck("Verify(ID2, m2, h2, r2)", verifyId2M2);
//        printCheck("Verify(ID1, m2, h2, r2)", verifyId1H2);
//        printCheck("Verify(ID2, m1, h2, r2)", verifyId2M1H2);
//        printCheck("Verify(ID2, m2, h1, r2)", verifyId2H1);
//        printCheck("Verify(ID2, m2, h2, r1)", verifyId2R1);

        assertTrue(verifyId1M1);
        assertFalse(verifyId2M1);
        assertFalse(verifyId1M2);
        assertTrue(verifyId2M2);
        assertFalse(verifyId1H2);
        assertFalse(verifyId2M1H2);
        assertFalse(verifyId2H1);
        assertFalse(verifyId2R1);

        ChameleonHash.IBCH.BaseIBCH.Components.Randomness r1Prime = pp.createRandomness();
        scheme.Collision(r1Prime, pp, id1, sk1, m1, h1, r1, m2);

        printStage("Collision");
        printComponent("消息2（嵌入前为\"msg2\"）", m2);
        printComponent("新随机值（对应消息\"msg2\"）", r1Prime);

        boolean verifyOriginal = scheme.Verify(pp, id1, m1, h1, r1);
        boolean verifyCollision = scheme.Verify(pp, id1, m2, h1, r1Prime);
        boolean verifyWrongCollision = scheme.Verify(pp, id1, m1, h1, r1Prime);

//        printCheck("Verify original pair after collision", verifyOriginal);
//        printCheck("Verify collided pair", verifyCollision);
//        printCheck("Verify old message with collided randomness", verifyWrongCollision);

        assertTrue(verifyOriginal, "Adapt(L1, m2) valid");
        assertTrue(verifyCollision, "Adapt(L1, m2) valid");
        assertFalse(verifyWrongCollision, "Adapt(L1, m1) invalid");
    }

    @Test
    @DisplayName("Print DSS_2019 components")
    void printDSS2019Components() {
        PBCHConfig schemeConfig = buildPBCHConfig(PBCHName.DSS_2019);
        printSchemeHeader("DSS+19", schemeConfig.curveConfig.curveName.name());

        BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.BasePBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.PBCH.BasePBCH.Components.MasterPublicKey mpk = pp.createMasterPublicKey();
        ChameleonHash.PBCH.BasePBCH.Components.MasterSecretKey msk = pp.createMasterSecretKey();

        scheme.Setup(pp, mpk, msk);
        printStage("Setup");
        printComponent("公共参数", pp);
        printComponent("主公钥", mpk);
        printComponent("主私钥", msk);

        ChameleonHash.PBCH.BasePBCH.Components.Policy policy = pp.createPolicy(DEFAULT_POLICY);
        ChameleonHash.PBCH.BasePBCH.Components.Attributes s1 = pp.createAttributes();
        ChameleonHash.PBCH.BasePBCH.Components.Attributes s2 = pp.createAttributes();
        s1.addAttr("A");
        s1.addAttr("DDDD");
        s2.addAttr("BB");
        s2.addAttr("CCC");

        printStage("Policy and Attributes");
        printComponent("policy", policy);
        printComponent("s1", s1);
        printComponent("s2", s2);

        ChameleonHash.PBCH.BasePBCH.Components.SecretKey sk1 = pp.createSecretKey();
        scheme.KeyGen(sk1, pp, mpk, msk, s1);
        ChameleonHash.PBCH.BasePBCH.Components.SecretKey sk2 = pp.createSecretKey();
        scheme.KeyGen(sk2, pp, mpk, msk, s2);

        printStage("KeyGen");
        printComponent("sk1", sk1);
        printComponent("sk2", sk2);

        ChameleonHash.PBCH.BasePBCH.Components.HashValue h1 = pp.createHashValue();
        ChameleonHash.PBCH.BasePBCH.Components.HashValue h2 = pp.createHashValue();
        ChameleonHash.PBCH.BasePBCH.Components.Randomness r1 = pp.createRandomness();
        ChameleonHash.PBCH.BasePBCH.Components.Randomness r2 = pp.createRandomness();
        ChameleonHash.PBCH.BasePBCH.Components.Randomness rPrime = pp.createRandomness();
        ChameleonHash.PBCH.BasePBCH.Components.Message m1 = pp.createMessage("msg1");
        ChameleonHash.PBCH.BasePBCH.Components.Message m2 = pp.createMessage("msg2");

        printStage("Messages");
        printComponent("m1", m1);
        printComponent("m2", m2);

        scheme.Hash(h1, r1, pp, mpk, m1, policy);
        scheme.Hash(h2, r2, pp, mpk, m2, policy);

        printStage("Hash");
        printComponent("h1", h1);
        printComponent("r1", r1);
        printComponent("h2", h2);
        printComponent("r2", r2);

        boolean verifyM1 = scheme.Verify(pp, mpk, m1, h1, r1);
        boolean verifyM2Wrong = scheme.Verify(pp, mpk, m2, h1, r1);
        boolean verifyM2 = scheme.Verify(pp, mpk, m2, h2, r2);
        boolean verifyM1Wrong = scheme.Verify(pp, mpk, m1, h2, r2);

        printStage("Verify");
        printCheck("Verify(m1, h1, r1)", verifyM1);
        printCheck("Verify(m2, h1, r1)", verifyM2Wrong);
        printCheck("Verify(m2, h2, r2)", verifyM2);
        printCheck("Verify(m1, h2, r2)", verifyM1Wrong);

        assertTrue(verifyM1, "H(m1) valid");
        assertFalse(verifyM2Wrong, "H(m2) invalid");
        assertTrue(verifyM2, "H(m2) valid");
        assertFalse(verifyM1Wrong, "H(m1) invalid");

        scheme.Collision(rPrime, pp, mpk, sk1, m1, h1, r1, m2);

        printStage("Collision");
        printComponent("rPrime", rPrime);

        boolean verifyCollision = scheme.Verify(pp, mpk, m2, h1, rPrime);
        boolean verifyWrongCollision = scheme.Verify(pp, mpk, m1, h1, rPrime);

        printCheck("Verify collided pair", verifyCollision);
        printCheck("Verify old message with collided randomness", verifyWrongCollision);

        assertTrue(verifyCollision, "Adapt(m2) valid");
        assertFalse(verifyWrongCollision, "Adapt(m1) invalid");
    }

    @Test
    @DisplayName("Print ZLW_2021 components")
    void printZLW2021Components() {
        PBCHConfig schemeConfig = buildPBCHConfig(PBCHName.ZLW_2021);
        printSchemeHeader("ZLW_2021", schemeConfig.curveConfig.curveName.name());

        MAPBCH scheme = MAPBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.MAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        scheme.Setup(pp);

        printStage("Setup");
        printComponent("pp", pp);

        int authNum = 6;
        ChameleonHash.PBCH.MAPBCH.Components.Authority[] auth = new ChameleonHash.PBCH.MAPBCH.Components.Authority[authNum];
        for (int i = 0; i < authNum; ++i) auth[i] = pp.createAuthority();
        for (int i = 0; i < authNum; ++i) auth[i].Setup(pp);
        auth[0].AddAttr(pp.createAttribute("A"));
        auth[1].AddAttr(pp.createAttribute("BB"));
        auth[2].AddAttr(pp.createAttribute("CCC"));
        auth[3].AddAttr(pp.createAttribute("DDDD"));

        printStage("Authorities");
        for (int i = 0; i < auth.length; ++i) {
            printComponent("auth[" + i + "]", auth[i]);
        }

        ChameleonHash.PBCH.MAPBCH.Components.User u1 = pp.createUser("user1");
        u1.Setup(pp);
        u1.AddAttr(pp.createAttribute("A"));
        u1.AddAttr(pp.createAttribute("DDDD"));
        for (int i = 0; i < authNum; ++i) u1.KeyGen(pp, auth[i]);

        ChameleonHash.PBCH.MAPBCH.Components.User u2 = pp.createUser("user2");
        u2.Setup(pp);
        u2.AddAttr(pp.createAttribute("BB"));
        u2.AddAttr(pp.createAttribute("CCC"));
        for (int i = 0; i < authNum; ++i) u2.KeyGen(pp, auth[i]);

        printStage("Users");
        printComponent("u1", u1);
        printComponent("u2", u2);

        ChameleonHash.PBCH.MAPBCH.Components.Message m1 = pp.createMessage("msg1");
        ChameleonHash.PBCH.MAPBCH.Components.Message m2 = pp.createMessage("msg2");
        ChameleonHash.PBCH.MAPBCH.Components.Policy policy = pp.createPolicy(DEFAULT_POLICY);
        ChameleonHash.PBCH.MAPBCH.Components.HashValue h1 = pp.createHashValue();
        ChameleonHash.PBCH.MAPBCH.Components.HashValue h2 = pp.createHashValue();
        ChameleonHash.PBCH.MAPBCH.Components.Randomness r1 = pp.createRandomness();
        ChameleonHash.PBCH.MAPBCH.Components.Randomness r2 = pp.createRandomness();
        ChameleonHash.PBCH.MAPBCH.Components.Randomness rPrime = pp.createRandomness();

        printStage("Policy and Messages");
        printComponent("policy", policy);
        printComponent("m1", m1);
        printComponent("m2", m2);

        u1.Hash(h1, r1, pp, policy, m1);
        printStage("Hash by u1");
        printComponent("h1", h1);
        printComponent("r1", r1);

        boolean verifyU1 = u1.Verify(pp, m1, h1, r1);
        boolean verifyU1Wrong = u1.Verify(pp, m2, h1, r1);
        printCheck("u1.Verify(m1, h1, r1)", verifyU1);
        printCheck("u1.Verify(m2, h1, r1)", verifyU1Wrong);
        assertTrue(verifyU1, "H(m1) valid");
        assertFalse(verifyU1Wrong, "H(m2) invalid");

        printStage("Unauthorized Collision Attempt");
        RuntimeException u2CollisionFailure = expectRuntimeException("u2 collision on h1 should fail", () -> {
            u2.Collision(rPrime, pp, m1, h1, r1, m2);
            assertFalse(u1.Verify(pp, m2, h1, rPrime), "H(m1) valid");
            assertFalse(u1.Verify(pp, m1, h1, rPrime), "H(m2) invalid");
        });
        printException("u2 collision on h1 should fail", u2CollisionFailure);

        u1.Collision(rPrime, pp, m1, h1, r1, m2);
        printStage("Authorized Collision");
        printComponent("rPrime", rPrime);

        boolean verifyU1Collision = u1.Verify(pp, m2, h1, rPrime);
        boolean verifyU1CollisionWrong = u1.Verify(pp, m1, h1, rPrime);
        printCheck("u1.Verify(m2, h1, rPrime)", verifyU1Collision);
        printCheck("u1.Verify(m1, h1, rPrime)", verifyU1CollisionWrong);
        assertTrue(verifyU1Collision, "H(m1) valid");
        assertFalse(verifyU1CollisionWrong, "H(m2) invalid");

        u2.Hash(h2, r2, pp, policy, m2);
        printStage("Hash by u2");
        printComponent("h2", h2);
        printComponent("r2", r2);

        boolean verifyU2 = u2.Verify(pp, m2, h2, r2);
        boolean verifyU2Wrong = u2.Verify(pp, m1, h2, r2);
        printCheck("u2.Verify(m2, h2, r2)", verifyU2);
        printCheck("u2.Verify(m1, h2, r2)", verifyU2Wrong);
        assertTrue(verifyU2, "H(m1) valid");
        assertFalse(verifyU2Wrong, "H(m2) invalid");
    }

    @Test
    @DisplayName("Print XNM_2021 components")
    void printXNM2021Components() {
        PBCHConfig schemeConfig = buildPBCHConfig(PBCHName.XNM_2021);
        printSchemeHeader("XNM_2021", schemeConfig.curveConfig.curveName.name());

        RevocablePBCH scheme = RevocablePBCHFactory.createScheme(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
        ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey mpk = pp.createMasterPublicKey();
        ChameleonHash.PBCH.RevocablePBCH.Components.Authority auth = pp.createAuthority();
        auth.Setup(mpk, pp);

        printStage("Setup");
        printComponent("pp", pp);
        printComponent("mpk", mpk);
        printComponent("auth", auth);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u1 = pp.createUser("u1");
        u1.S.addAttr("A");
        u1.S.addAttr("DDDD");
        auth.KeyGen(u1, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u2 = pp.createUser("u2");
        u2.S.addAttr("BB");
        u2.S.addAttr("CCC");
        auth.KeyGen(u2, pp, mpk);

        ChameleonHash.PBCH.RevocablePBCH.Components.User u3 = pp.createUser("u3");
        u3.S.addAttr("A");
        u3.S.addAttr("BB");
        u3.S.addAttr("CCC");
        auth.KeyGen(u3, pp, mpk);

        printStage("Users After KeyGen");
        printComponent("u1", u1);
        printComponent("u2", u2);
        printComponent("u3", u3);

        ChameleonHash.PBCH.RevocablePBCH.Components.Message m1 = pp.createMessage("msg1");
        ChameleonHash.PBCH.RevocablePBCH.Components.Message m2 = pp.createMessage("msg2");
        ChameleonHash.PBCH.RevocablePBCH.Components.Message m3 = pp.createMessage("msg3");
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h1 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h2 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.HashValue h3 = pp.createHashValue();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r1 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r2 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness r3 = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Randomness rPrime = pp.createRandomness();
        ChameleonHash.PBCH.RevocablePBCH.Components.Policy policy = pp.createPolicy(DEFAULT_POLICY);
        ChameleonHash.PBCH.RevocablePBCH.Components.Info info = pp.createInfo();
        setTimestamp(info, 5);

        printStage("Policy, Info and Messages");
        printComponent("policy", policy);
        printComponent("info@5", info);
        printComponent("m1", m1);
        printComponent("m2", m2);
        printComponent("m3", m3);
        printComponent("h3 (unused placeholder)", h3);
        printComponent("r3 (unused placeholder)", r3);

        u1.Hash(h1, r1, pp, mpk, m1, policy, info);
        printStage("Hash by u1");
        printComponent("h1", h1);
        printComponent("r1", r1);

        boolean verifyU1M1 = u1.Verify(pp, mpk, m1, h1, r1);
        boolean verifyU1M2 = u1.Verify(pp, mpk, m2, h1, r1);
        boolean verifyU1M3 = u1.Verify(pp, mpk, m3, h1, r1);
        printCheck("u1.Verify(m1, h1, r1)", verifyU1M1);
        printCheck("u1.Verify(m2, h1, r1)", verifyU1M2);
        printCheck("u1.Verify(m3, h1, r1)", verifyU1M3);
        assertTrue(verifyU1M1, "H(m1) valid");
        assertFalse(verifyU1M2, "H(m2) invalid");
        assertFalse(verifyU1M3, "H(m3) invalid");

        auth.KeyUpdate(pp, mpk, info);
        auth.DecryptKeyGen(u1, pp, mpk);
        auth.DecryptKeyGen(u2, pp, mpk);
        auth.DecryptKeyGen(u3, pp, mpk);

        printStage("After KeyUpdate@5 and DecryptKeyGen");
        printComponent("auth", auth);
        printComponent("u1", u1);
        printComponent("u2", u2);
        printComponent("u3", u3);

        u1.Collision(rPrime, pp, mpk, m1, h1, r1, m2);
        printStage("Authorized Collision at timestamp 5");
        printComponent("rPrime", rPrime);

        boolean verifyU1Collision = u1.Verify(pp, mpk, m2, h1, rPrime);
        boolean verifyU1CollisionWrong = u1.Verify(pp, mpk, m1, h1, rPrime);
        printCheck("u1.Verify(m2, h1, rPrime)", verifyU1Collision);
        printCheck("u1.Verify(m1, h1, rPrime)", verifyU1CollisionWrong);
        assertTrue(verifyU1Collision);
        assertFalse(verifyU1CollisionWrong);

        RuntimeException u2Failure = expectRuntimeException("u2 collision at timestamp 5 should fail", () -> {
            u2.Collision(rPrime, pp, mpk, m1, h1, r1, m2);
            if (!u2.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u2 cannot verify collision at timestamp 5");
        });
        printException("u2 collision at timestamp 5 should fail", u2Failure);

        u3.Collision(rPrime, pp, mpk, m1, h1, r1, m2);
        printStage("u3 Collision at timestamp 5");
        printComponent("rPrime", rPrime);

        boolean verifyU3Collision = u3.Verify(pp, mpk, m2, h1, rPrime);
        boolean verifyU3CollisionWrong = u3.Verify(pp, mpk, m1, h1, rPrime);
        printCheck("u3.Verify(m2, h1, rPrime)", verifyU3Collision);
        printCheck("u3.Verify(m1, h1, rPrime)", verifyU3CollisionWrong);
        assertTrue(verifyU3Collision);
        assertFalse(verifyU3CollisionWrong);

        setTimestamp(info, 10);
        auth.Revoke(pp, mpk, u1, info);
        printStage("Revoke u1 at timestamp 10");
        printComponent("info@10", info);
        printComponent("auth", auth);

        setTimestamp(info, 50);
        u2.Hash(h2, r2, pp, mpk, m1, policy, info);
        printStage("Hash by u2 at timestamp 50");
        printComponent("info@50", info);
        printComponent("h2", h2);
        printComponent("r2", r2);

        auth.KeyUpdate(pp, mpk, info);
        auth.DecryptKeyGen(u1, pp, mpk);
        auth.DecryptKeyGen(u2, pp, mpk);
        auth.DecryptKeyGen(u3, pp, mpk);

        printStage("After KeyUpdate@50 and DecryptKeyGen");
        printComponent("auth", auth);
        printComponent("u1", u1);
        printComponent("u2", u2);
        printComponent("u3", u3);

        RuntimeException revokedU1Failure = expectRuntimeException("u1 collision at timestamp 50 should fail", () -> {
            u1.Collision(rPrime, pp, mpk, m2, h2, r2, m2);
            if (!u1.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u1 cannot verify collision at timestamp 50");
        });
        printException("u1 collision at timestamp 50 should fail", revokedU1Failure);

        RuntimeException u2FailureAt50 = expectRuntimeException("u2 collision at timestamp 50 should fail", () -> {
            u2.Collision(rPrime, pp, mpk, m2, h2, r2, m2);
            if (!u2.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u2 cannot verify collision at timestamp 50");
        });
        printException("u2 collision at timestamp 50 should fail", u2FailureAt50);

        u3.Collision(rPrime, pp, mpk, m1, h2, r2, m2);
        printStage("u3 Collision at timestamp 50");
        printComponent("rPrime", rPrime);

        boolean verifyU3AfterRevoke = u3.Verify(pp, mpk, m2, h2, rPrime);
        boolean verifyU3AfterRevokeWrong = u3.Verify(pp, mpk, m1, h2, rPrime);
        printCheck("u3.Verify(m2, h2, rPrime)", verifyU3AfterRevoke);
        printCheck("u3.Verify(m1, h2, rPrime)", verifyU3AfterRevokeWrong);
        assertTrue(verifyU3AfterRevoke);
        assertFalse(verifyU3AfterRevokeWrong);

        setTimestamp(info, 100);
        auth.Revoke(pp, mpk, u2, info);
        auth.KeyUpdate(pp, mpk, info);
        auth.DecryptKeyGen(u1, pp, mpk);
        auth.DecryptKeyGen(u2, pp, mpk);
        auth.DecryptKeyGen(u3, pp, mpk);

        printStage("After Revoke u2 at timestamp 100");
        printComponent("info@100", info);
        printComponent("auth", auth);
        printComponent("u1", u1);
        printComponent("u2", u2);
        printComponent("u3", u3);

        RuntimeException u1FailureAt100 = expectRuntimeException("u1 collision at timestamp 100 should fail", () -> {
            u1.Collision(rPrime, pp, mpk, m2, h2, r2, m2);
            if (!u1.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u1 cannot verify collision at timestamp 100");
        });
        printException("u1 collision at timestamp 100 should fail", u1FailureAt100);

        RuntimeException u2FailureAt100 = expectRuntimeException("u2 collision at timestamp 100 should fail", () -> {
            u2.Collision(rPrime, pp, mpk, m2, h2, r2, m2);
            if (!u2.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u2 cannot verify collision at timestamp 100");
        });
        printException("u2 collision at timestamp 100 should fail", u2FailureAt100);

        RuntimeException u3FailureAt100 = expectRuntimeException("u3 collision at timestamp 100 should fail", () -> {
            u3.Collision(rPrime, pp, mpk, m2, h2, r2, m2);
            if (!u3.Verify(pp, mpk, m2, h1, rPrime)) throw new RuntimeException("u3 cannot verify collision at timestamp 100");
        });
        printException("u3 collision at timestamp 100 should fail", u3FailureAt100);
    }

    private static CHConfig buildCCT2024Config() {
        Map<String, Object> params = new HashMap<>();
        params.put("curve_group", CurveGroup.G1);
        params.put("pke_config", new PKEConfig(PKEName.RSA));
        Config curveConfig = new Config(CURVE_NAME, new HashMap<>());
        CHConfig schemeConfig = new CHConfig(CHName.CCT_2024, curveConfig, params);
        params.put("ch_config", schemeConfig);
        return schemeConfig;
    }

    private static IBCHConfig buildXSL2021Config() {
        Map<String, Object> params = new HashMap<>();
        params.put("ID_Binary_Len", XSL_ID_BINARY_LEN);
        Config curveConfig = new Config(CURVE_NAME, new HashMap<>());
        return new IBCHConfig(IBCHName.XSL_2021, curveConfig, params);
    }

    private static PBCHConfig buildPBCHConfig(PBCHName schemeName) {
        CurveName curveName = schemeName.schemeCurveRequire == ChameleonHash.SchemeCurveRequire.SYMMETRIC
                ? CurveName.A
                : CURVE_NAME;
        Config curveConfig = new Config(curveName, new HashMap<>());
        Map<String, Object> params = new HashMap<>();

        Map<String, Object> chParam = new HashMap<>();
        chParam.put("curve_group", CurveGroup.G1);
        Map<String, Object> chetParam = new HashMap<>();
        chetParam.put("ch_config", new CHConfig(CHName.DSS_2020, curveConfig, chParam));
        params.put("chet_config", new CHConfig(CHName.BC_CDK_2017, curveConfig, chetParam));

        Map<String, Object> seParam = new HashMap<>();
        seParam.put("algorithm", "AES");
        seParam.put("transformation", "AES/ECB/PKCS5Padding");
        params.put("se_config", new SEConfig(SEName.AES, seParam));

        params.put("id_len", 32);
        params.put("max_user", 2048);
        params.put("curve_group", CurveGroup.G1);

        if (schemeName.multi_auth) {
            params.put("maabe_config", new ABEConfig(ABEName.MAABE_RW_2015, curveConfig));
        }

        return new PBCHConfig(schemeName, curveConfig, params);
    }

    private static void setTimestamp(ChameleonHash.PBCH.RevocablePBCH.Components.Info info, int timestamp) {
        HashMap<String, Object> value = new HashMap<>();
        value.put("timestamp", timestamp);
        info.setValue(value);
    }

    private static RuntimeException expectRuntimeException(String label, Executable executable) {
        return assertThrows(RuntimeException.class, executable, label);
    }

    private static void printSchemeHeader(String schemeName, String curveName) {
        System.out.println();
        String scheme = "方案: " + schemeName;
        String curve = "曲线: " + curveName;
        String bar = "=".repeat(1 + (scheme.length() + 2) + 3 + (curve.length() + 2) + 1);
        System.out.println(bar);
        System.out.println(" " + scheme + " | " + curve);
        System.out.println(bar);
    }

    private static void printStage(String title) {
        System.out.println();
        String bar = "-".repeat(20);
        System.out.println(bar + " " + title + " 阶段 " + bar);
    }

    private static void printCheck(String label, boolean result) {
        System.out.println(label + " = " + result);
    }

    private static void printException(String label, RuntimeException exception) {
        System.out.println(label + " -> expected exception: " + exception.getClass().getSimpleName()
                + (exception.getMessage() == null ? "" : " | " + exception.getMessage()));
    }

    private static void printComponent(String label, Object value) {
        System.out.println(label + " = " + dumpValue(value));
    }

    private static String dumpValue(Object value) {
        return renderValue(value, 0, new IdentityHashMap<>(), null);
    }

    private static String renderValue(Object value, int depth, IdentityHashMap<Object, Boolean> visited, String contextName) {
        if (value == null) return "null";
        if (depth >= MAX_DUMP_DEPTH) return simplePrefix(value) + "{...}";

        Class<?> clazz = value.getClass();
        if (isSimpleValue(clazz) || value instanceof Scalar || value instanceof BitSet) {
            return formatSimpleValue(value);
        }
        if (value instanceof MultivePoint) {
            return formatPointValue(value, !"treeNode".equals(contextName));
        }

        if (visited.put(value, Boolean.TRUE) != null) {
            return "<visited " + simplePrefix(value) + ">";
        }

        if (clazz.isArray()) return renderArray(value, depth, visited, contextName);
        if (value instanceof Collection<?>) return renderCollection((Collection<?>) value, depth, visited);
        if (value instanceof Map<?, ?>) return renderMap((Map<?, ?>) value, depth, visited);
        if (shouldTreatAsOpaque(clazz)) return simplePrefix(value) + "(" + safeToString(value) + ")";

        StringBuilder sb = new StringBuilder();
        sb.append(simplePrefix(value)).append(" {\n");
        boolean hasField = false;
        for (Class<?> current = clazz; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic() || shouldSkipField(field)) continue;
                String prefix = indent(depth + 1) + field.getName() + " = ";
                try {
                    field.setAccessible(true);
                    Object fieldValue = field.get(value);
                    if (shouldSkipFieldValue(field, fieldValue)) continue;

                    hasField = true;
                    String renderedValue = alignMultiline(
                            renderFieldValue(value, field.getName(), fieldValue, depth + 1, visited),
                            prefix.length()
                    );
                    sb.append(prefix).append(renderedValue);
                } catch (Throwable e) {
                    hasField = true;
                    sb.append(prefix)
                            .append("<inaccessible: ")
                            .append(e.getClass().getSimpleName())
                            .append(">");
                }
                sb.append('\n');
            }
        }
        if (!hasField) {
            sb.append(indent(depth + 1)).append(safeToString(value)).append('\n');
        }
        sb.append(indent(depth)).append('}');
        return sb.toString();
    }

    private static String renderFieldValue(
            Object owner,
            String fieldName,
            Object fieldValue,
            int depth,
            IdentityHashMap<Object, Boolean> visited
    ) {
        String blackBoxSummary = summarizeBlackBoxComponent(owner, fieldName);
        if (blackBoxSummary != null) {
            return blackBoxSummary;
        }
        if (fieldValue instanceof BitSet) {
            return formatBitSet((BitSet) fieldValue, inferBitSetLength(owner, fieldName, (BitSet) fieldValue));
        }
        return renderValue(fieldValue, depth, visited, fieldName);
    }

    private static String renderArray(Object array, int depth, IdentityHashMap<Object, Boolean> visited, String contextName) {
        Class<?> componentType = array.getClass().getComponentType();
        if (componentType.isPrimitive()) {
            if (componentType == byte.class) return formatByteArray((byte[]) array);
            if (componentType == int.class) return Arrays.toString((int[]) array);
            if (componentType == long.class) return Arrays.toString((long[]) array);
            if (componentType == boolean.class) return Arrays.toString((boolean[]) array);
            if (componentType == short.class) return Arrays.toString((short[]) array);
            if (componentType == char.class) return Arrays.toString((char[]) array);
            if (componentType == float.class) return Arrays.toString((float[]) array);
            if (componentType == double.class) return Arrays.toString((double[]) array);
        }

        if ("g_theta".equals(contextName)) {
            return renderBinaryTreeArray(array, depth, visited);
        }

        if (componentType.isArray()) {
            return renderTwoDimensionalArray(array, depth, visited);
        }

        int len = Array.getLength(array);
        StringBuilder sb = new StringBuilder();
        sb.append(componentType.getSimpleName()).append("[").append(len).append("] [\n");
        int[] previewRange = previewRange(len);
        for (int i = 0; i < previewRange[0]; ++i) {
            String prefix = indent(depth + 1) + i + " = ";
            sb.append(prefix)
                    .append(alignMultiline(
                            renderValue(Array.get(array, i), depth + 1, visited, null),
                            prefix.length()
                    ))
                    .append('\n');
        }
        if (len > MAX_CONTAINER_PREVIEW) {
            sb.append(indent(depth + 1))
                    .append("... 折叠 ")
                    .append(len - previewRange[0] - previewRange[1])
                    .append(" 个元素 ...\n");
            for (int i = len - previewRange[1]; i < len; ++i) {
                String prefix = indent(depth + 1) + i + " = ";
                sb.append(prefix)
                        .append(alignMultiline(
                                renderValue(Array.get(array, i), depth + 1, visited, null),
                                prefix.length()
                        ))
                        .append('\n');
            }
        }
        sb.append(indent(depth)).append(']');
        return sb.toString();
    }

    private static String renderTwoDimensionalArray(Object array, int depth, IdentityHashMap<Object, Boolean> visited) {
        int rowCount = Array.getLength(array);
        Class<?> rowType = array.getClass().getComponentType();
        Class<?> elementType = rowType.getComponentType();

        StringBuilder sb = new StringBuilder();
        sb.append(elementType.getSimpleName())
                .append("[")
                .append(rowCount)
                .append("][")
                .append(inferColumnCount(array))
                .append("] {\n");

        int[] previewRange = previewRange(rowCount);
        for (int i = 0; i < previewRange[0]; ++i) {
            sb.append(indent(depth + 1))
                    .append(formatArrayRow(Array.get(array, i), depth + 1, visited));
            if (i + 1 < rowCount) sb.append(',');
            sb.append('\n');
        }

        if (rowCount > MAX_CONTAINER_PREVIEW) {
            sb.append(indent(depth + 1))
                    .append("... 折叠 ")
                    .append(rowCount - previewRange[0] - previewRange[1])
                    .append(" 个元素 ...\n");
            for (int i = rowCount - previewRange[1]; i < rowCount; ++i) {
                sb.append(indent(depth + 1))
                        .append(formatArrayRow(Array.get(array, i), depth + 1, visited));
                if (i + 1 < rowCount) sb.append(',');
                sb.append('\n');
            }
        }

        sb.append(indent(depth)).append('}');
        return sb.toString();
    }

    private static int inferColumnCount(Object array) {
        int rowCount = Array.getLength(array);
        for (int i = 0; i < rowCount; ++i) {
            Object row = Array.get(array, i);
            if (row != null && row.getClass().isArray()) {
                return Array.getLength(row);
            }
        }
        return 0;
    }

    private static String formatArrayRow(Object rowArray, int depth, IdentityHashMap<Object, Boolean> visited) {
        if (rowArray == null) return "{null}";

        int len = Array.getLength(rowArray);
        StringBuilder sb = new StringBuilder();
        sb.append('{');

        int[] previewRange = previewRange(len);
        boolean needsSeparator = false;
        for (int i = 0; i < previewRange[0]; ++i) {
            if (needsSeparator) sb.append(", ");
            sb.append(renderValue(Array.get(rowArray, i), depth + 1, visited, null));
            needsSeparator = true;
        }

        if (len > MAX_CONTAINER_PREVIEW) {
            if (needsSeparator) sb.append(", ");
            sb.append("... 折叠 ")
                    .append(len - previewRange[0] - previewRange[1])
                    .append(" 个元素 ...");
            needsSeparator = true;
            for (int i = len - previewRange[1]; i < len; ++i) {
                if (needsSeparator) sb.append(", ");
                sb.append(renderValue(Array.get(rowArray, i), depth + 1, visited, null));
                needsSeparator = true;
            }
        }

        sb.append('}');
        return sb.toString();
    }

    private static String renderBinaryTreeArray(Object array, int depth, IdentityHashMap<Object, Boolean> visited) {
        int len = Array.getLength(array);
        int nonNullCount = 0;
        for (int i = 0; i < len; ++i) {
            if (Array.get(array, i) != null) ++nonNullCount;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(array.getClass().getComponentType().getSimpleName())
                .append("[")
                .append(len)
                .append("] <binary tree> {\n");
        sb.append(indent(depth + 1)).append("nonNullNodes = ").append(nonNullCount).append('\n');

        if (nonNullCount == 0) {
            sb.append(indent(depth + 1)).append("<all nodes are null>\n");
        } else {
            int level = 0;
            int start = 0;
            while (start < len) {
                int levelSize = Math.min(1 << level, len - start);
                StringBuilder levelLine = new StringBuilder();
                int levelNonNull = 0;
                for (int i = start; i < start + levelSize; ++i) {
                    Object node = Array.get(array, i);
                    if (node == null) continue;
                    if (levelNonNull > 0) levelLine.append(", ");
                    String prefix = "[" + i + "]=";
                    levelLine.append(prefix)
                            .append(alignMultiline(
                                    renderValue(node, depth + 2, visited, "treeNode"),
                                    prefix.length()
                            ));
                    ++levelNonNull;
                }
                if (levelNonNull > 0) {
                    sb.append(indent(depth + 1))
                            .append("level ")
                            .append(level)
                            .append(": ")
                            .append(levelLine)
                            .append('\n');
                }
                start += levelSize;
                ++level;
            }
        }

        sb.append(indent(depth)).append('}');
        return sb.toString();
    }

    private static String renderCollection(Collection<?> collection, int depth, IdentityHashMap<Object, Boolean> visited) {
        StringBuilder sb = new StringBuilder();
        sb.append(collection.getClass().getSimpleName()).append(" [\n");
        int index = 0;
        int[] previewRange = previewRange(collection.size());
        for (Object item : collection) {
            if (index >= previewRange[0]) break;
            String prefix = indent(depth + 1) + index + " = ";
            sb.append(prefix)
                    .append(alignMultiline(
                            renderValue(item, depth + 1, visited, null),
                            prefix.length()
                    ))
                    .append('\n');
            ++index;
        }
        if (collection.size() > MAX_CONTAINER_PREVIEW) {
            sb.append(indent(depth + 1))
                    .append("... 折叠 ")
                    .append(collection.size() - previewRange[0] - previewRange[1])
                    .append(" 个元素 ...\n");
            int tailStart = collection.size() - previewRange[1];
            index = 0;
            for (Object item : collection) {
                if (index >= tailStart) {
                    String prefix = indent(depth + 1) + index + " = ";
                    sb.append(prefix)
                            .append(alignMultiline(
                                    renderValue(item, depth + 1, visited, null),
                                    prefix.length()
                            ))
                            .append('\n');
                }
                ++index;
            }
        }
        sb.append(indent(depth)).append(']');
        return sb.toString();
    }

    private static String renderMap(Map<?, ?> map, int depth, IdentityHashMap<Object, Boolean> visited) {
        StringBuilder sb = new StringBuilder();
        sb.append(map.getClass().getSimpleName()).append(" {\n");
        int[] previewRange = previewRange(map.size());
        int index = 0;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (index >= previewRange[0]) break;
            String keyText = renderValue(entry.getKey(), depth + 1, visited, null);
            String prefix = indent(depth + 1) + keyText + " -> ";
            sb.append(prefix)
                    .append(alignMultiline(
                            renderValue(entry.getValue(), depth + 1, visited, null),
                            prefix.length()
                    ))
                    .append('\n');
            ++index;
        }
        if (map.size() > MAX_CONTAINER_PREVIEW) {
            sb.append(indent(depth + 1))
                    .append("... 折叠 ")
                    .append(map.size() - previewRange[0] - previewRange[1])
                    .append(" 个元素 ...\n");
            int tailStart = map.size() - previewRange[1];
            index = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (index >= tailStart) {
                    String keyText = renderValue(entry.getKey(), depth + 1, visited, null);
                    String prefix = indent(depth + 1) + keyText + " -> ";
                    sb.append(prefix)
                            .append(alignMultiline(
                                    renderValue(entry.getValue(), depth + 1, visited, null),
                                    prefix.length()
                            ))
                            .append('\n');
                }
                ++index;
            }
        }
        sb.append(indent(depth)).append('}');
        return sb.toString();
    }

    private static int[] previewRange(int size) {
        if (size <= MAX_CONTAINER_PREVIEW) return new int[]{size, 0};
        return new int[]{CONTAINER_HEAD_PREVIEW, CONTAINER_TAIL_PREVIEW};
    }

    private static boolean shouldSkipFieldValue(Field field, Object fieldValue) {
        String typeName = field.getType().getName();
        if (typeName.startsWith("ChameleonHash.Interface.")
                || typeName.startsWith("Encryption.Interface.")) {
            return true;
        }

        if (fieldValue == null) return false;

        String valueClassName = fieldValue.getClass().getName();
        return field.getName().endsWith("Scheme")
                || "Scheme".equals(fieldValue.getClass().getSimpleName())
                || valueClassName.endsWith(".Scheme");
    }

    private static boolean shouldSkipField(Field field) {
        if (SKIPPED_FIELD_NAMES.contains(field.getName())) return true;

        Class<?> type = field.getType();
        String typeName = type.getName();
        return type == Random.class
                || typeName.equals("EllipticCurve.Curve.Curve")
                || typeName.equals("EllipticCurve.Curve.Config")
                || typeName.startsWith("java.security.")
                || typeName.startsWith("javax.crypto.")
                || typeName.endsWith(".Scheme");
    }

    private static boolean shouldTreatAsOpaque(Class<?> clazz) {
        String name = clazz.getName();
        return name.startsWith("EllipticCurve.Curve.implement.")
                || name.startsWith("it.unisa.dia.gas.")
                || name.startsWith("com.herumi.mcl.")
                || name.startsWith("java.lang.reflect.");
    }

    private static boolean isSimpleValue(Class<?> clazz) {
        return clazz.isPrimitive()
                || clazz == String.class
                || clazz == BigInteger.class
                || Number.class.isAssignableFrom(clazz)
                || clazz == Boolean.class
                || clazz == Character.class
                || clazz.isEnum();
    }

    private static String formatSimpleValue(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return "\"" + value + "\"";
        if (value instanceof Byte) return formatByte((Byte) value);
        if (value instanceof BitSet) return formatBitSet((BitSet) value);
        return value.toString();
    }

    private static String formatPointValue(Object value, boolean multiline) {
        String raw = safeToString(value).trim();
        if (raw.isEmpty()) return "[]";
        if (raw.indexOf('\n') >= 0 || raw.startsWith("[") || raw.startsWith("{")) return raw;

        String[] coordinates = raw.split("\\s+");
        if (coordinates.length <= 1) return raw;

        String separator = multiline ? ",\n" : ", ";
        return "[" + String.join(separator, coordinates) + "]";
    }

    private static String alignMultiline(String text, int continuationIndent) {
        if (text == null || text.indexOf('\n') < 0) return text;
        return text.replace("\n", "\n" + " ".repeat(Math.max(0, continuationIndent)));
    }

    private static String summarizeBlackBoxComponent(Object owner, String fieldName) {
        int split = fieldName.indexOf('_');
        if (split <= 0 || split >= fieldName.length() - 1) return null;

        String family = fieldName.substring(0, split).toUpperCase(Locale.ROOT);
        if ("FAME".equals(family)) return null;
        String schemeName = inferBlackBoxSchemeName(owner, family);
        if (schemeName == null) return null;

        String componentRole = describeBlackBoxComponentRole(fieldName.substring(split + 1));
        return "黑盒" + family + "的" + componentRole + "，本次运行选取方案 " + schemeName + "。";
    }

    private static String describeBlackBoxComponentRole(String suffix) {
        switch (suffix) {
            case "pp":
                return "公共参数";
            case "mpk":
                return "主公钥";
            case "msk":
                return "主私钥";
            case "pk":
                return "公钥";
            case "sk":
                return "私钥";
            case "ct":
                return "密文";
            case "m":
                return "消息";
            case "h":
                return "哈希值";
            case "r":
                return "随机值";
            case "dk":
                return "解密密钥";
            case "uk":
                return "更新密钥";
            case "st":
                return "状态";
            case "rl":
                return "撤销列表";
            default:
                return "组件";
        }
    }

    private static String inferBlackBoxSchemeName(Object owner, String family) {
        String ownerClassName = owner == null ? "" : owner.getClass().getName();
        if ("CHET".equals(family)) return "BC_CDK_2017";
        if ("CH".equals(family)) return "DSS_2020";
        if ("SE".equals(family)) return "AES";
        if ("FAME".equals(family)) return "FAME";
        if ("MAABE".equals(family)) return "MAABE_RW_2015";
        if ("RABE".equals(family)) {
            if (ownerClassName.contains("XNM_2021")) return "XNM_2021";
            if (ownerClassName.contains("TMM_2022")) return "TMM_2022";
            return "RABE";
        }
        return null;
    }

    private static String formatByte(byte value) {
        return "0x" + toHexByte(value);
    }

    private static String formatByteArray(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 + bytes.length * 2);
        sb.append("0x");
        for (byte value : bytes) {
            sb.append(toHexByte(value));
        }
        return sb.toString();
    }

    private static String toHexByte(byte value) {
        int unsigned = value & 0xFF;
        return new String(new char[]{
                HEX_DIGITS[(unsigned >>> 4) & 0x0F],
                HEX_DIGITS[unsigned & 0x0F]
        });
    }

    private static String formatBitSet(BitSet bitSet) {
        return formatBitSet(bitSet, bitSet.length());
    }

    private static String formatBitSet(BitSet bitSet, int bitLength) {
        if (bitLength <= 0) return "0";

        StringBuilder sb = new StringBuilder(bitLength);
        for (int i = 0; i < bitLength; ++i) {
            sb.append(bitSet.get(i) ? '1' : '0');
        }
        return sb.toString();
    }

    private static int inferBitSetLength(Object owner, String fieldName, BitSet bitSet) {
        if (owner != null && ("tag".equals(fieldName) || "tag_g".equals(fieldName))) {
            Integer gThetaLength = tryReadArrayLength(owner, "g_theta");
            if (gThetaLength != null && gThetaLength > 0) return gThetaLength;
        }

        if (owner != null && "I".equals(fieldName) && owner.getClass().getName().contains("XSL_2021")) {
            return XSL_ID_BINARY_LEN;
        }

        Integer ownerN = tryReadIntField(owner, "n");
        if (ownerN != null && ownerN > 0) return ownerN;

        return bitSet.length();
    }

    private static Integer tryReadIntField(Object owner, String fieldName) {
        Object fieldValue = tryReadField(owner, fieldName);
        return fieldValue instanceof Integer ? (Integer) fieldValue : null;
    }

    private static Integer tryReadArrayLength(Object owner, String fieldName) {
        Object fieldValue = tryReadField(owner, fieldName);
        return fieldValue != null && fieldValue.getClass().isArray() ? Array.getLength(fieldValue) : null;
    }

    private static Object tryReadField(Object owner, String fieldName) {
        if (owner == null) return null;
        for (Class<?> current = owner.getClass(); current != null && current != Object.class; current = current.getSuperclass()) {
            try {
                Field field = current.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(owner);
            } catch (NoSuchFieldException ignored) {
                // Continue searching parent classes.
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
    }

    private static String formatSequence(String[] elements, boolean multiline) {
        String separator = multiline ? ",\n" : ", ";
        if (elements.length <= MAX_CONTAINER_PREVIEW) {
            return "[" + String.join(separator, elements) + "]";
        }

        int[] previewRange = previewRange(elements.length);
        String[] visible = new String[previewRange[0] + previewRange[1] + 1];
        for (int i = 0; i < previewRange[0]; ++i) {
            visible[i] = elements[i];
        }
        visible[previewRange[0]] = "... 折叠 " + (elements.length - previewRange[0] - previewRange[1]) + " 个元素 ...";
        for (int i = 0; i < previewRange[1]; ++i) {
            visible[previewRange[0] + 1 + i] = elements[elements.length - previewRange[1] + i];
        }
        return "[" + String.join(separator, visible) + "]";
    }

    private static String simplePrefix(Object value) {
        return value == null ? "null" : value.getClass().getSimpleName();
    }

    private static String safeToString(Object value) {
        try {
            return value.toString();
        } catch (Throwable e) {
            return "<toString failed: " + e.getClass().getSimpleName() + ">";
        }
    }

    private static String indent(int depth) {
        return "  ".repeat(Math.max(0, depth));
    }
}
