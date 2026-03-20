package PerformTest.PBCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHName;
import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.BAPBCH.BAPBCHFactory;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
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
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class TheoStorageTest {
    static public final String file_base_name = "theo_storage_cost";

    static List<PBCHName> skipList = List.of(new PBCHName[]{
    });

    public static Stream<Arguments> GetAllPBCHScheme() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    public static Stream<Arguments> GetAllPBCHSchemeASCurve() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    @BeforeAll
    static void initTest() {
        for (PBCHName value : PBCHName.values()) new File(String.format("./data/PBCH/%s", value.name())).mkdirs();
    }

    @DisplayName("test PBCH theory storage cost")
    @Nested
    class CHTSCTest {
        private void testFunc(BufferedWriter theo_storage_cost, PBCHConfig schemeConfig) throws IOException {
            System.out.println("\n\nRunning " + schemeConfig.schemeName);
            if (schemeConfig.schemeName.has_blackbox_accountability) testBAPBCH(theo_storage_cost, schemeConfig);
//            else if (schemeConfig.schemeName.has_ET) testCHET(theo_storage_cost, schemeConfig);
            else testBasePBCH(theo_storage_cost, schemeConfig);
        }

        private void testBasePBCH(BufferedWriter theo_storage_cost, PBCHConfig schemeConfig) throws IOException {
            BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
            PublicParam pp = scheme.createPublicParam(schemeConfig);
            MasterPublicKey mpk = pp.createMasterPublicKey();
            MasterSecretKey msk = pp.createMasterSecretKey();

            scheme.Setup(pp, mpk, msk);

            Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");
            Attributes S = pp.createAttributes();
            S.addAttr("A");
            S.addAttr("DDDD");

            SecretKey sk = pp.createSecretKey();
            scheme.KeyGen(sk, pp, mpk, msk, S);

            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();
            Message m = pp.createMessage("msg1");
            scheme.Hash(h, r, pp, mpk, m, P);

            System.out.println("PublicParam: " + pp.TheoSize());
            System.out.println("MasterPublicKey: " + mpk.TheoSize());
            System.out.println("MasterSecretKey: " + msk.TheoSize());
            System.out.println("SecretKey: " + sk.TheoSize());
//            System.out.println("Policy: " + P.TheoSize());
//            System.out.println("Attributes: " + S.TheoSize());
            System.out.println("Message: " + m.TheoSize());
            System.out.println("HashValue: " + h.TheoSize());
            System.out.println("Randomness: " + r.TheoSize());
            System.out.println();

            theo_storage_cost.write("PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, " +
//                    "Policy, Attributes, " +
                    "Message, HashValue, Randomness\n");
            theo_storage_cost.write(
                    pp.TheoSize() + "," + mpk.TheoSize() + "," + msk.TheoSize() + "," +
                            sk.TheoSize() + "," +
//                            P.TheoSize() + "," + S.TheoSize() + "," +
                            m.TheoSize() + "," +
                            h.TheoSize() + "," + r.TheoSize() + "\n"
            );
            theo_storage_cost.close();
        }


        private void testBAPBCH(BufferedWriter theo_storage_cost, PBCHConfig schemeConfig) throws IOException {
            BAPBCH scheme = BAPBCHFactory.createScheme(schemeConfig);
            ChameleonHash.PBCH.BAPBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            MasterPublicKey mpk = pp.createMasterPublicKey();
            MasterSecretKey msk = pp.createMasterSecretKey();

            scheme.Setup(pp, mpk, msk);

            Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");

            User u = pp.createUser(((int) schemeConfig.params.get("id_len")) / 3);
            scheme.AssignUser(u, pp, mpk, msk);
            u.S.addAttr("A");
            u.S.addAttr("DDDD");
            scheme.KeyGen(u, pp, mpk, msk);

            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();
            Message m = pp.createMessage("msg1");
            scheme.Hash(h, r, pp, mpk, u, m, P);

            System.out.println("PublicParam: " + pp.TheoSize());
            System.out.println("MasterPublicKey: " + mpk.TheoSize());
            System.out.println("MasterSecretKey: " + msk.TheoSize());
            System.out.println("SecretKey: " + u.sk.TheoSize());
            System.out.println("User: " + (u.TheoSize() + " + A + SK"));
//            System.out.println("Policy: " + P.TheoSize());
//            System.out.println("Attributes: " + S.TheoSize());
            System.out.println("Message: " + m.TheoSize());
            System.out.println("HashValue: " + h.TheoSize());
            System.out.println("Randomness: " + r.TheoSize());
            System.out.println();

            theo_storage_cost.write("PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, User, " +
//                    "Policy, Attributes, " +
                    "Message, HashValue, Randomness\n");
            theo_storage_cost.write(
                    pp.TheoSize() + "," + mpk.TheoSize() + "," + msk.TheoSize() + "," +
                            u.sk.TheoSize() + "," + (u.TheoSize() + " + A + SK") + "," +
//                            P.TheoSize() + "," + S.TheoSize() + "," +
                            m.TheoSize() + "," +
                            h.TheoSize() + "," + r.TheoSize() + "\n"
            );
            theo_storage_cost.close();
        }

//        private void testCHET(BufferedWriter theo_storage_cost, CHConfig schemeConfig) throws IOException {
//            CHET scheme = CHETFactory.createScheme(schemeConfig);
//            ChameleonHash.CH.CHET.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
//            scheme.Setup(pp);
//            PublicKey pk = pp.createPublicKey();
//            SecretKey sk = pp.createSecretKey();
//            scheme.KeyGen(pk, sk, pp);
//            Message m = pp.createMessage("msg");
//            HashValue h = pp.createHashValue();
//            Randomness r = pp.createRandomness();
//            ETrapdoor etd = pp.createETrapdoor();
//            scheme.Hash(h, r, pp, pk, m, etd);
//
//            System.out.println("PublicParam: " + pp.TheoSize());
//            System.out.println("PublicKey: " + pk.TheoSize());
//            System.out.println("SecretKey: " + sk.TheoSize());
//            System.out.println("Message: " + m.TheoSize());
//            System.out.println("ETrapdoor: " + etd.TheoSize());
//            System.out.println("HashValue: " + h.TheoSize());
//            System.out.println("Randomness: " + r.TheoSize());
//            System.out.println();
//
//            theo_storage_cost.write("PublicParam, PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness\n");
//            theo_storage_cost.write(
//                    pp.TheoSize() + "," + pk.TheoSize() + "," + sk.TheoSize() + "," +
//                            m.TheoSize() + "," + etd.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
//            );
//            theo_storage_cost.close();
//        }
//
//        private void testLabelCH(BufferedWriter theo_storage_cost, CHConfig schemeConfig) throws IOException {
//            LabelCH scheme = LabelCHFactory.createScheme(schemeConfig);
//            ChameleonHash.CH.LabelCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
//            scheme.Setup(pp);
//            PublicKey pk = pp.createPublicKey();
//            SecretKey sk = pp.createSecretKey();
//            scheme.KeyGen(pk, sk, pp);
//            Message m = pp.createMessage("msg");
//            Label l = pp.createLabel("label");
//            HashValue h = pp.createHashValue();
//            Randomness r = pp.createRandomness();
//            scheme.Hash(h, r, pp, pk, m, l);
//
//            System.out.println("PublicParam: " + pp.TheoSize());
//            System.out.println("PublicKey: " + pk.TheoSize());
//            System.out.println("SecretKey: " + sk.TheoSize());
//            System.out.println("Message: " + m.TheoSize());
//            System.out.println("Label: " + l.TheoSize());
//            System.out.println("HashValue: " + h.TheoSize());
//            System.out.println("Randomness: " + r.TheoSize());
//            System.out.println();
//
//            theo_storage_cost.write("PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness\n");
//            theo_storage_cost.write(
//                    pp.TheoSize() + "," + pk.TheoSize() + "," + sk.TheoSize() + "," +
//                            m.TheoSize() + "," + l.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
//            );
//            theo_storage_cost.close();
//        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.PBCH.TheoStorageTest#GetAllPBCHScheme")
        public void DSTest(PBCHName schemeName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            Config curveConfig = new Config(CurveName.E, curve_param);
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
            PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);

            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/PBCH/%s/%s.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }

        @DisplayName("test swap G1 and G2 implement")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.PBCH.TheoStorageTest#GetAllPBCHSchemeASCurve")
        public void SGGTest(PBCHName schemeName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            Config curveConfig = new Config(CurveName.E, curve_param);
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
            PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);

            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/PBCH/%s/%s_swapG1G2.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }
//
//        @DisplayName("swap G1 and G2")
//        @ParameterizedTest(name = "test scheme {0}")
//        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHSchemeASCurve")
//        public void SGGTest(PBCHName schemeName) throws IOException {
//            Map<String, Object> curve_param = new HashMap<>();
//            curve_param.put("swap_G1G2", true);
//            Config curveConfig = new Config(E, curve_param);
//            Map<String, Object> params = new HashMap<>();
//            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
//            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s_swapG1G2.csv", schemeName.name(), file_base_name)));
//            testFunc(theo_storage_cost, schemeConfig);
//        }

//        @DisplayName("test single group scheme")
//        @ParameterizedTest(name = "test scheme {0}")
//        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHSchemeSingleGroup")
//        void CHSingleGroupTest(PBCHName schemeName) throws IOException {
//            Map<String, Object> params = new HashMap<>();
//            Map<String, Object> curve_param = new HashMap<>();
//            params.put("curve_group", CurveGroup.G1);
//            Config curveConfig = new Config(E, curve_param);
//            params.put("pke_config", new PKEConfig(PKEName.RSA));
//            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
//            CHConfig BC_CH = new CHConfig(PBCHName.CCT_2024, curveConfig, params);
//            params.put("ch_config", BC_CH);
//            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s.csv", schemeName.name(), file_base_name)));
//            testFunc(theo_storage_cost, schemeConfig);
//        }
    }
}
