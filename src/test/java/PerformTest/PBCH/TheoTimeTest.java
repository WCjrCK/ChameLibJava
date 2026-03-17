package PerformTest.PBCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.CH.CHName;
import ChameleonHash.CH.Components.*;
import ChameleonHash.CH.LabelCH.Components.Label;
import ChameleonHash.CH.LabelCH.LabelCHFactory;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.Interface.CHET;
import ChameleonHash.Interface.LabelCH;
import ChameleonHash.PBCH.BasePBCH.BasePBCHFactory;
import ChameleonHash.PBCH.Components.Attributes;
import ChameleonHash.PBCH.Components.MasterPublicKey;
import ChameleonHash.PBCH.Components.MasterSecretKey;
import ChameleonHash.PBCH.Components.Policy;
import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.PBCHName;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import Encryption.SE.SEConfig;
import Encryption.SE.SEName;
import PerformTest.TraceScope;
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

public class TheoTimeTest {
    static public final String file_base_name = "theo_time_cost";

    static List<PBCHName> skipList = List.of(new PBCHName[]{
    });

    public static Stream<Arguments> GetAllPBCHScheme() {
        return EnumSet.allOf(PBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    public static Stream<Arguments> GetAllCHSchemeASCurve() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SINGLEGROUP)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    public static Stream<Arguments> GetAllCHSchemeSingleGroup() {
        return EnumSet.allOf(CHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire == SchemeCurveRequire.SINGLEGROUP)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    @BeforeAll
    static void initTest() {
        for (CHName value : CHName.values()) new File(String.format("./data/CH/%s", value.name())).mkdirs();
    }

    @DisplayName("test CH theory storage cost")
    @Nested
    class CHTSCTest {
        private void testFunc(BufferedWriter theo_time_cost, PBCHConfig schemeConfig) throws IOException {
            System.out.println("\n\nRunning " + schemeConfig.schemeName);
//            if (schemeConfig.schemeName.has_label) testLabelCH(theo_time_cost, schemeConfig);
//            else if (schemeConfig.schemeName.has_ET) testCHET(theo_time_cost, schemeConfig);
//            else
                testBaseCH(theo_time_cost, schemeConfig);
        }

        private void testBaseCH(BufferedWriter theo_time_cost, PBCHConfig schemeConfig) throws IOException {
            BasePBCH scheme = BasePBCHFactory.createScheme(schemeConfig);
            ChameleonHash.PBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            MasterPublicKey mpk = pp.createMasterPublicKey();
            MasterSecretKey msk = pp.createMasterSecretKey();

            theo_time_cost.write("Setup, KeyGen, Hash, Ver, Col\n");

            try (AutoCloseable ignored = TraceScope.begin()) {
                pp = scheme.createPublicParam(schemeConfig);
                scheme.Setup(pp, mpk, msk);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Setup cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            Policy P = pp.createPolicy("A&(DDDD|(BB&CCC))");
            Attributes S = pp.createAttributes();
            S.addAttr("A");
            S.addAttr("DDDD");

            ChameleonHash.PBCH.Components.SecretKey sk = pp.createSecretKey();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.KeyGen(sk, pp, mpk, msk, S);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("KeyGen cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.PBCH.Components.Message m = pp.createMessage("msg1");
            ChameleonHash.PBCH.Components.HashValue h = pp.createHashValue();
            ChameleonHash.PBCH.Components.Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, pp, mpk, m, P);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Hash cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.PBCH.Components.Message m_p = pp.createMessage("msg2");
            ChameleonHash.PBCH.Components.Randomness r_p = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Verify(pp, mpk, m, h, r);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Ver cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Collision(r_p, pp, mpk, sk, m, P, h, r, m_p);
                theo_time_cost.write(TraceScope.getData());
                System.out.println("Col cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            theo_time_cost.close();
        }

        private void testCHET(BufferedWriter theo_time_cost, CHConfig schemeConfig) throws IOException {
            CHET scheme = CHETFactory.createScheme(schemeConfig);
            ChameleonHash.CH.CHET.Components.PublicParam pp;

            theo_time_cost.write("Setup, KeyGen, Hash, Ver, Col\n");

            try (AutoCloseable ignored = TraceScope.begin()) {
                pp = scheme.createPublicParam(schemeConfig);
                scheme.Setup(pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Setup cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            PublicKey pk = pp.createPublicKey();
            SecretKey sk = pp.createSecretKey();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.KeyGen(pk, sk, pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("KeyGen cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            Message m = pp.createMessage("msg");
            ETrapdoor etd = pp.createETrapdoor();
            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, pp, pk, m, etd);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Hash cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            Message m1 = pp.createMessage("msg1");
            Randomness r1 = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Verify(pp, pk, m, h, r);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Ver cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Collision(r1, pp, pk, sk, m, etd, h, r, m1);
                theo_time_cost.write(TraceScope.getData());
                System.out.println("Col cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            theo_time_cost.close();
        }

        private void testLabelCH(BufferedWriter theo_time_cost, CHConfig schemeConfig) throws IOException {
            LabelCH scheme = LabelCHFactory.createScheme(schemeConfig);
            ChameleonHash.CH.LabelCH.Components.PublicParam pp;

            theo_time_cost.write("Setup, KeyGen, Hash, Ver, Col\n");

            try (AutoCloseable ignored = TraceScope.begin()) {
                pp = scheme.createPublicParam(schemeConfig);
                scheme.Setup(pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Setup cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            PublicKey pk = pp.createPublicKey();
            SecretKey sk = pp.createSecretKey();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.KeyGen(pk, sk, pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("KeyGen cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            Message m = pp.createMessage("msg");
            Label l = pp.createLabel("label");
            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, pp, pk, m, l);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Hash cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            Message m1 = pp.createMessage("msg1");
            Randomness r1 = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Verify(pp, pk, m, l, h, r);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Ver cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }


            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Collision(r1, pp, pk, sk, m, l, h, r, m1);
                System.out.println("Col cost:" + TraceScope.getData());
                theo_time_cost.write(TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            theo_time_cost.close();
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.PBCH.TheoTimeTest#GetAllPBCHScheme")
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
            PBCHConfig schemeConfig = new PBCHConfig(schemeName, curveConfig, params);

            BufferedWriter theo_time_cost = new BufferedWriter(new FileWriter(String.format("./data/PBCH/%s/%s.csv", schemeName.name(), file_base_name)));
            testFunc(theo_time_cost, schemeConfig);
        }
//
//        @DisplayName("swap G1 and G2")
//        @ParameterizedTest(name = "test scheme {0}")
//        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHSchemeASCurve")
//        public void SGGTest(CHName schemeName) throws IOException {
//            Map<String, Object> curve_param = new HashMap<>();
//            curve_param.put("swap_G1G2", true);
//            Config curveConfig = new Config(E, curve_param);
//            Map<String, Object> params = new HashMap<>();
//            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
//            BufferedWriter theo_time_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s_swapG1G2.csv", schemeName.name(), file_base_name)));
//            testFunc(theo_time_cost, schemeConfig);
//        }

//        @DisplayName("test single group scheme")
//        @ParameterizedTest(name = "test scheme {0}")
//        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHSchemeSingleGroup")
//        void CHSingleGroupTest(CHName schemeName) throws IOException {
//            Map<String, Object> params = new HashMap<>();
//            Map<String, Object> curve_param = new HashMap<>();
//            params.put("curve_group", CurveGroup.G1);
//            params.put("pke_config", new PKEConfig(PKEName.RSA));
//            Config curveConfig = new Config(E, curve_param);
//            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
//            CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
//            params.put("ch_config", BC_CH);
//            BufferedWriter theo_time_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s.csv", schemeName.name(), file_base_name)));
//            testFunc(theo_time_cost, schemeConfig);
//        }
    }
}
