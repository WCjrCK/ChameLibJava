package PBCTest.CHTest;

import PBCTest.BasicParam;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import scheme.CH.CHET_RSA_CDK_2017.Native;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("NewClassNamingConvention")
public class CHET_RSA_CDK_2017 extends BasicParam {
    double[] time_cost = new double[4];

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/CH/CHET_RSA_CDK_2017.txt"));
            File_Writer.write(String.format("repeat count: %d\n", repeat_cnt));
            File_Writer.write("CHET_RSA_CDK_2017\t\t\tKeyGen, Hash, Check, Adapt\n");
            System.out.println("CHET_RSA_CDK_2017");
            System.out.println("\t\t\tKeyGen, Hash, Check, Adapt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test CHET_RSA_CDK_2017")
    @ParameterizedTest(name = "test k = {0}")
    @ValueSource(ints = {256, 512, 1024})
    void NativeTest(int k) {
        try {
            File_Writer.write(String.format("k:%d: ", k));
            System.out.printf("k:%d: ", k);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Random rand = new Random();
        Native scheme = new Native(k);

        Native.PublicKey[] pk = new Native.PublicKey[repeat_cnt];
        Native.SecretKey[] sk = new Native.SecretKey[repeat_cnt];
        Native.HashValue[] h = new Native.HashValue[repeat_cnt];
        Native.Randomness[] r = new Native.Randomness[repeat_cnt];
        Native.Randomness[] rp = new Native.Randomness[repeat_cnt];
        Native.ETrapdoor[] etd = new Native.ETrapdoor[repeat_cnt];
        BigInteger[] m = new BigInteger[repeat_cnt];
        BigInteger[] m2 = new BigInteger[repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) {
            pk[i] = new Native.PublicKey();
            sk[i] = new Native.SecretKey();
            m[i] = new BigInteger(k / 2, rand);
            m2[i] = new BigInteger(k / 2, rand);
            h[i] = new Native.HashValue();
            r[i] = new Native.Randomness();
            rp[i] = new Native.Randomness();
            etd[i] = new Native.ETrapdoor();
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Hash(h[i], r[i], etd[i], pk[i], m[i]);
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
            for(int i = 0;i < repeat_cnt;++i) scheme.Adapt(rp[i], h[i], r[i], etd[i], pk[i], sk[i], m[i], m2[i]);
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
        try {
            for (double x : time_cost) File_Writer.write(String.format("%.6f, ", x));
            File_Writer.write("\n");
            for (double x : time_cost) System.out.printf("%.6f, ", x);
            System.out.println();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterAll
    static void afterAll() {
        try {
            File_Writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
