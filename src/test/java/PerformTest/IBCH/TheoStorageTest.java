package PerformTest.IBCH;

import EllipticCurve.Curve.Config;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import ChameleonHash.IBCH.Components.*;
import ChameleonHash.IBCH.IBCH;
import ChameleonHash.SchemeCurveRequire;
import ChameleonHash.SchemeFactory;
import ChameleonHash.SchemeName;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static EllipticCurve.Curve.CurveName.E;

public class TheoStorageTest {
    static public final String file_base_name = "theo_storage_cost";

    static List<SchemeName> skipList = List.of(new SchemeName[]{
//            IBCH_ZSS_2003_S1,
//            IBCH_ZSS_2003_S2,
//            IBCH_CZS_2014,
//            IBCH_LSX_2022,
//            IBCH_XSL_2021,
//            IBCH_LJF_2025,
    });

    @BeforeAll
    static void initTest() {
        for (SchemeName value : SchemeName.values()) new File(String.format("./data/IBCH/%s", value.name())).mkdirs();
    }

    @DisplayName("test IBCH theory storage cost")
    @Nested
    class IBCHTSCTest {
        private void testFunc(BufferedWriter theo_storage_cost, ChameleonHash.Config schemeConfig) throws IOException {
            IBCH scheme = (IBCH) SchemeFactory.createScheme(schemeConfig);
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
            theo_storage_cost.write("PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness\n");
            theo_storage_cost.write(
                    pp.TheoSize() + "," + msk.TheoSize() + "," + sk.TheoSize() + "," + ID.TheoSize() + "," +
                            m.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
            );
            theo_storage_cost.close();
        }

        @DisplayName("test direct scheme")
        @ParameterizedTest(name = "test scheme {0}")
        @EnumSource
        public void DSTest(SchemeName schemeName) throws IOException {
            if (skipList.contains(schemeName)) return;
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", false);
            Config curveConfig = new Config(E, curve_param);
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 100);
            ChameleonHash.Config schemeConfig = new ChameleonHash.Config(schemeName, curveConfig, params);
            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/%s.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }

        @DisplayName("swap G1 and G2")
        @ParameterizedTest(name = "test scheme {0}")
        @EnumSource
        public void SGGTest(SchemeName schemeName) throws IOException {
            if (skipList.contains(schemeName)) return;
            if (schemeName.schemeCurveRequire == SchemeCurveRequire.SYMMETRIC) {
                System.out.println("对称方案，无需交换G1 G2");
                return;
            }
            Map<String, Object> curve_param = new HashMap<>();
            curve_param.put("swap_G1G2", true);
            Config curveConfig = new Config(E, curve_param);
            Map<String, Object> params = new HashMap<>();
            params.put("ID_Binary_Len", 100);
            ChameleonHash.Config schemeConfig = new ChameleonHash.Config(schemeName, curveConfig, params);
            BufferedWriter theo_storage_cost = new BufferedWriter(new FileWriter(String.format("./data/IBCH/%s/%s_swapG1G2.csv", schemeName.name(), file_base_name)));
            testFunc(theo_storage_cost, schemeConfig);
        }
    }
}
