package PerformTest.CH;

import ChameleonHash.CH.BaseCH.BaseCHFactory;
import ChameleonHash.CH.BaseCH.Components.*;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.CHETFactory;
import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.CH.CHName;
import ChameleonHash.CH.LabelCH.Components.Label;
import ChameleonHash.CH.LabelCH.LabelCHFactory;
import ChameleonHash.Interface.BaseCH;
import ChameleonHash.Interface.CHET;
import ChameleonHash.Interface.LabelCH;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.CurveGroup;
import Encryption.PKE.PKEConfig;
import Encryption.PKE.PKEName;
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

import static EllipticCurve.Curve.CurveName.E;

public class TheoTimeTest {
    static public final String file_base_name = "theo_time_cost";

    static List<CHName> skipList = List.of(new CHName[]{
    });

    public static Stream<Arguments> GetAllCHScheme() {
        return EnumSet.allOf(CHName.class).stream()
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
        private void testFunc(BufferedWriter theo_time_cost, CHConfig schemeConfig) throws IOException {
            System.out.println("\n\nRunning " + schemeConfig.schemeName);
            if (schemeConfig.schemeName.has_label) testLabelCH(theo_time_cost, schemeConfig);
            else if (schemeConfig.schemeName.has_ET) testCHET(theo_time_cost, schemeConfig);
            else testBaseCH(theo_time_cost, schemeConfig);
        }

        private void testBaseCH(BufferedWriter theo_time_cost, CHConfig schemeConfig) throws IOException {
            BaseCH scheme = BaseCHFactory.createScheme(schemeConfig);
            PublicParam pp;

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
            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, pp, pk, m);
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
                scheme.Collision(r1, pp, pk, sk, m, h, r, m1);
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
            ChameleonHash.CH.CHET.Components.PublicKey pk = pp.createPublicKey();
            ChameleonHash.CH.CHET.Components.SecretKey sk = pp.createSecretKey();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.KeyGen(pk, sk, pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("KeyGen cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.CH.CHET.Components.Message m = pp.createMessage("msg");
            ETrapdoor etd = pp.createETrapdoor();
            ChameleonHash.CH.CHET.Components.HashValue h = pp.createHashValue();
            ChameleonHash.CH.CHET.Components.Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, etd, pp, pk, m);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Hash cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.CH.CHET.Components.Message m1 = pp.createMessage("msg1");
            ChameleonHash.CH.CHET.Components.Randomness r1 = pp.createRandomness();

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
            ChameleonHash.CH.LabelCH.Components.PublicKey pk = pp.createPublicKey();
            ChameleonHash.CH.LabelCH.Components.SecretKey sk = pp.createSecretKey();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.KeyGen(pk, sk, pp);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("KeyGen cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.CH.LabelCH.Components.Message m = pp.createMessage("msg");
            Label l = pp.createLabel("label");
            ChameleonHash.CH.LabelCH.Components.HashValue h = pp.createHashValue();
            ChameleonHash.CH.LabelCH.Components.Randomness r = pp.createRandomness();

            try (AutoCloseable ignored = TraceScope.begin()) {
                scheme.Hash(h, r, pp, pk, m, l);
                theo_time_cost.write(TraceScope.getData() + ",");
                System.out.println("Hash cost:" + TraceScope.getData());
                TraceScope.getUnknownFunc();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ChameleonHash.CH.LabelCH.Components.Message m1 = pp.createMessage("msg1");
            ChameleonHash.CH.LabelCH.Components.Randomness r1 = pp.createRandomness();

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

//        @DisplayName("test direct scheme")
//        @ParameterizedTest(name = "test scheme {0}")
//        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHScheme")
//        public void DSTest(CHName schemeName) throws IOException {
//            Map<String, Object> curve_param = new HashMap<>();
//            curve_param.put("swap_G1G2", false);
//            Config curveConfig = new Config(E, curve_param);
//            Map<String, Object> params = new HashMap<>();
//            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
//            BufferedWriter theo_time_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s.csv", schemeName.name(), file_base_name)));
//            testFunc(theo_time_cost, schemeConfig);
//        }
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

        @DisplayName("test single group scheme")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.CH.TheoTimeTest#GetAllCHSchemeSingleGroup")
        void CHSingleGroupTest(CHName schemeName) throws IOException {
            Map<String, Object> params = new HashMap<>();
            Map<String, Object> curve_param = new HashMap<>();
            params.put("curve_group", CurveGroup.G1);
            params.put("pke_config", new PKEConfig(PKEName.RSA));
            Config curveConfig = new Config(E, curve_param);
            CHConfig schemeConfig = new CHConfig(schemeName, curveConfig, params);
            CHConfig BC_CH = new CHConfig(CHName.CCT_2024, curveConfig, params);
            params.put("ch_config", BC_CH);
            BufferedWriter theo_time_cost = new BufferedWriter(new FileWriter(String.format("./data/CH/%s/%s.csv", schemeName.name(), file_base_name)));
            testFunc(theo_time_cost, schemeConfig);
        }
    }
}
