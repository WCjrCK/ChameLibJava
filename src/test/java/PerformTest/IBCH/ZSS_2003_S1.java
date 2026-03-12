package PerformTest.IBCH;

import org.junit.jupiter.api.BeforeAll;
import scheme.IBCH.IBCH;
import scheme.IBCH.implement.ZSS_2003.PublicParam;
import scheme.IBCH.implement.ZSS_2003.S1.*;
import scheme.SchemeFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static EllipticCurve.Curve.CurveName.E;
import static PerformTest.BasicParam.*;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static scheme.SchemeName.IBCH_ZSS_2003_S1;
import static utils.Func.InitialLib;

public class ZSS_2003_S1 {
    double[] time_cost = new double[5];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            real_time_cost = new BufferedWriter(new FileWriter(String.format("./data/IBCH/ZSS_2003_S1/real_time_cost_%d.csv", repeat_cnt)));
            real_time_cost.write("Curve, Setup, KeyGen, Hash, Ver, Col\n");

            theo_time_cost = new BufferedWriter(new FileWriter("./data/IBCH/ZSS_2003_S1/theo_time_cost.csv"));

//            theo_storage_cost = new BufferedWriter(new FileWriter("./data/IBCH/ZSS_2003_S1/theo_storage_cost.csv"));
//            Map<String, Object> params = new HashMap<>();
//            Map<String, Object> curve_param = new HashMap<>();
//            params.put("curve_param", curve_param);
//            IBCH scheme = (IBCH) SchemeFactory.createScheme(IBCH_ZSS_2003_S1, E, params);
//            PublicParam pp = (PublicParam) SchemeFactory.createPublicParam(IBCH_ZSS_2003_S1, E, params);
//            MasterSecretKey msk = new MasterSecretKey();
//            scheme.Setup(pp, msk);
//            SecretKey sk = new SecretKey();
//            Identity ID = new Identity("ID1");
//            scheme.KeyGen(sk, pp, msk, ID);
//            Message m = new Message("msg");
//            HashValue h = new HashValue();
//            Randomness r = new Randomness();
//            scheme.Hash(h, r, pp, ID, m);
//            theo_storage_cost.write("PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness\n");
//            theo_storage_cost.write(
//                    pp.TheoSize() + "," + msk.TheoSize() + "," + sk.TheoSize() + "," + ID.TheoSize() +
//                            m.TheoSize() + "," + h.TheoSize() + "," + r.TheoSize() + "\n"
//            );
//            theo_storage_cost.close();

            System.out.println("IB_CH_ZSS_S1_2003");
            System.out.println("Curve\t\t\tSetUp, KeyGen, Hash, Ver, Col");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
