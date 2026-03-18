package PerformTest.IBCH;

import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.BaseIBCH.Components.*;
import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.IBCH.IBCHName;
import ChameleonHash.IBCH.LabelIBCH.Components.Label;
import ChameleonHash.IBCH.LabelIBCH.LabelIBCHFactory;
import ChameleonHash.Interface.BaseIBCH;
import ChameleonHash.Interface.LabelIBCH;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.Config;
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

public class TheoStorageTest {
    static public final String file_base_name = "theo_storage_cost";

    static List<IBCHName> skipList = List.of(new IBCHName[]{
//            IBCH_ZSS_2003_S1,
//            IBCH_ZSS_2003_S2,
//            IBCH_CZS_2014,
//            IBCH_LSX_2022,
//            IBCH_XSL_2021,
//            IBCH_LJF_2025,
    });

    public static Stream<Arguments> GetAllIBCHScheme() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    public static Stream<Arguments> GetAllIBCHSchemeASCurve() {
        return EnumSet.allOf(IBCHName.class).stream()
                .filter(a -> !skipList.contains(a))
                .filter(a -> a.schemeCurveRequire != SchemeCurveRequire.SYMMETRIC)
                .flatMap(a -> Stream.of(Arguments.of(a)));
    }

    @BeforeAll
    static void initTest() {
        for (IBCHName value : IBCHName.values()) new File(String.format("./data/IBCH/%s", value.name())).mkdirs();
    }

    @DisplayName("test IBCH theory storage cost")
    @Nested
    class IBCHTSCTest {
        private void testFunc(BufferedWriter theo_storage_cost, IBCHConfig schemeConfig) throws IOException {
            System.out.println("\n\nRunning " + schemeConfig.schemeName);
            if (schemeConfig.schemeName.has_label) testLabelIBCH(theo_storage_cost, schemeConfig);
            else testBaseIBCH(theo_storage_cost, schemeConfig);
        }

        private void testBaseIBCH(BufferedWriter theo_storage_cost, IBCHConfig schemeConfig) throws IOException {
            BaseIBCH scheme = BaseIBCHFactory.createScheme(schemeConfig);
            PublicParam pp = scheme.createPublicParam(schemeConfig);
            MasterSecretKey msk = pp.createMasterSecretKey();
            scheme.Setup(pp, msk);
            SecretKey sk = pp.createSecretKey();
            Identity ID = pp.createIdentity("ID1");
            scheme.KeyGen(sk, pp, msk, ID);
            Message m = pp.createMessage("msg");
            HashValue h = pp.createHashValue();
            Randomness r = pp.createRandomness();
            scheme.Hash(h, r, pp, ID, m);

            System.out.println("PublicParam: " + pp.TheoSize());
            System.out.println("MasterSecretKey: " + msk.TheoSize());
            System.out.println("SecretKey: " + sk.TheoSize());
            System.out.println("Identity: " + ID.TheoSize());
            System.out.println("Message: " + m.TheoSize());
            System.out.println("HashValue: " + h.TheoSize());
            System.out.println("Randomness: " + r.TheoSize());
            System.out.println();

            theo_storage_cost.write("PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness\n");
            theo_storage_cost.write(
                    pp.TheoSize() + "," + msk.TheoSize() + "," + sk.TheoSize() + "," + ID.TheoSize() + "," +
                            m.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
            );
            theo_storage_cost.close();
        }

        private void testLabelIBCH(BufferedWriter theo_storage_cost, IBCHConfig schemeConfig) throws IOException {
            LabelIBCH scheme = LabelIBCHFactory.createScheme(schemeConfig);
            ChameleonHash.IBCH.LabelIBCH.Components.PublicParam pp = scheme.createPublicParam(schemeConfig);
            ChameleonHash.IBCH.LabelIBCH.Components.MasterSecretKey msk = pp.createMasterSecretKey();
            scheme.Setup(pp, msk);
            ChameleonHash.IBCH.LabelIBCH.Components.SecretKey sk = pp.createSecretKey();
            ChameleonHash.IBCH.LabelIBCH.Components.Identity ID = pp.createIdentity("ID1");
            scheme.KeyGen(sk, pp, msk, ID);
            ChameleonHash.IBCH.LabelIBCH.Components.Message m = pp.createMessage("msg");
            Label l = pp.createLabel("label");
            ChameleonHash.IBCH.LabelIBCH.Components.HashValue h = pp.createHashValue();
            ChameleonHash.IBCH.LabelIBCH.Components.Randomness r = pp.createRandomness();
            scheme.Hash(h, r, pp, ID, m, l);

            System.out.println("PublicParam: " + pp.TheoSize());
            System.out.println("MasterSecretKey: " + msk.TheoSize());
            System.out.println("SecretKey: " + sk.TheoSize());
            System.out.println("Identity: " + ID.TheoSize());
            System.out.println("Message: " + m.TheoSize());
            System.out.println("Label: " + l.TheoSize());
            System.out.println("HashValue: " + h.TheoSize());
            System.out.println("Randomness: " + r.TheoSize());
            System.out.println();

            theo_storage_cost.write("PublicParam, MasterSecretKey, SecretKey, Identity, Message, Label, HashValue, Randomness\n");
            theo_storage_cost.write(
                    pp.TheoSize() + "," + msk.TheoSize() + "," + sk.TheoSize() + "," + ID.TheoSize() + "," +
                            m.TheoSize() + "," + l.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
            );
            theo_storage_cost.close();
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.IBCH.TheoStorageTest#GetAllIBCHScheme")
        public void DSTest(IBCHName schemeName) throws IOException {
            if (skipList.contains(schemeName)) return;
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", false);
            Config curveConfig = new Config(E, curve_param);
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 100);
            IBCHConfig schemeConfig = new IBCHConfig(schemeName, curveConfig, params);
            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/%s.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0}")
        @MethodSource("PerformTest.IBCH.TheoStorageTest#GetAllIBCHSchemeASCurve")
        public void SGGTest(IBCHName schemeName) throws IOException {
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            Config curveConfig = new Config(E, curve_param);
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 100);
            IBCHConfig schemeConfig = new IBCHConfig(schemeName, curveConfig, params);
            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/%s_swapG1G2.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }
    }
}
