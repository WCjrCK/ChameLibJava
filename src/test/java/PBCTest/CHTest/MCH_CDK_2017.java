package PBCTest.CHTest;

import PBCTest.BasicParam;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import scheme.CH.MCH_CDK_2017.Native;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class MCH_CDK_2017 extends BasicParam {
    double[] time_cost = new double[4];

    @BeforeAll
    static void initTest() {
        InitialLib();
        System.out.println("MCH_CDK_2017");
        System.out.println("\t\t\tKeyGen, Hash, Check, Adapt");
    }

    @DisplayName("test MCH_CDK_2017")
    @ParameterizedTest(name = "test k = {0}")
    @ValueSource(ints = {256, 512, 1024})
    void NativeTest(int k) {
        System.out.printf("k = %d: ", k);
        Random rand = new Random();
        Native scheme = new Native(k);

        Native.PublicKey[] pk = new Native.PublicKey[repeat_cnt];
        Native.SecretKey[] sk = new Native.SecretKey[repeat_cnt];
        Native.HashValue[] h = new Native.HashValue[repeat_cnt];
        Native.Randomness[] r = new Native.Randomness[repeat_cnt];
        Native.Randomness[] rp = new Native.Randomness[repeat_cnt];
        String[] m = new String[repeat_cnt];
        String[] m2 = new String[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new Native.PublicKey();
            sk[i] = new Native.SecretKey();
            m[i] = new BigInteger(k / 2, rand).toString();
            m2[i] = new BigInteger(k / 2, rand).toString();
            h[i] = new Native.HashValue();
            r[i] = new Native.Randomness();
            rp[i] = new Native.Randomness();
        }

        int stage_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.KeyGen(pk[i], sk[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], r[i], pk[i], m[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
            assertTrue(res, "Hash Check Failed");
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], r[i], pk[i], sk[i], m[i], m2[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            time_cost[++stage_id] = duration / repeat_cnt;
        }

        {
            boolean res = true;
            for(int i = 0;i < repeat_cnt;++i) res &= scheme.Check(h[i], rp[i], pk[i], m2[i]);
            assertTrue(res, "Adapt Check Failed");
        }

    }

    @AfterEach
    void afterEach() {
        for (double x : time_cost) System.out.printf("%.6f, ", x);
        System.out.println();
    }
}
