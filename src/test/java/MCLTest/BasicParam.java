package MCLTest;

import curve.MCL;
import org.junit.jupiter.params.provider.Arguments;
import utils.BooleanFormulaParser;

import java.io.BufferedWriter;
import java.util.*;
import java.util.stream.Stream;

@SuppressWarnings("unused")
public class BasicParam {
    static public BufferedWriter File_Writer;
    static Random RAND = new Random();
    static public int diff_max_len = 17, repeat_cnt = 1;
    static public double[][] op_time = {
            {0.017611, 0.040673, 0.198593, 0.000364, 0.024948, 0.042032, 0.200090, 0.001204, 0.000217, 0.000493, 0.000646, 0.000167, 0.020964, 0.035852, 0.064566, 0.000037, 0.141005},
            {0.076516, 0.120330, 0.570225, 0.000142, 0.070493, 0.124304, 0.577646, 0.000417, 0.000432, 0.001020, 0.001145, 0.000031, 0.041352, 0.070940, 0.118363, 0.000034, 0.373586},
            {0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000}
    };

    static public List<Integer> BT_leaf_num = List.of(1024, 2048, 4096);
    static public List<Integer> IdentityLen = List.of(64, 128, 256);
    static public List<Integer> RSA_bit_len = List.of(256, 512, 1024);
    static public List<Integer> RSA_bit_len_small = List.of(64, 128, 256);
    static public List<Integer> Auth_num = List.of(256, 512, 1024);
    static public List<MCL> curves = List.of(MCL.BN254, MCL.BLS12_381);

    static public HashMap<MCL, Integer> index_map = new HashMap<>() {{
        put(MCL.BN254, 0);
        put(MCL.BLS12_381, 1);
        put(MCL.SECP256K1, 2);
    }};

    public static Stream<Arguments> GetMCLInvertIdentityLen() {
        return curves.stream().flatMap(a ->
                IdentityLen.stream().flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

    public static String RandomPolicyGenerator(BooleanFormulaParser.AttributeList access, boolean addit, int dep) {
        boolean endit = (RAND.nextInt(1 << dep) <= 1);
        boolean isAND = RAND.nextBoolean();
        String L, R;
        if (endit) {
            L = String.valueOf(RAND.nextLong());
            R = String.valueOf(RAND.nextLong());
            if (addit) {
                access.attrs.add(L);
                if (isAND) access.attrs.add(R);
            }
        } else {
            L = RandomPolicyGenerator(access, addit, dep - 1);
            R = RandomPolicyGenerator(access, addit && isAND, dep - 1);
        }
        if (isAND) return String.format("(%s&%s)", L, R);
        else return String.format("(%s|%s)", L, R);
    }

    public boolean CalDiff(int index, int[] ops, double real_time) {
        double expect_time = 0;
        for(int i = 0; i < diff_max_len; i++) expect_time += op_time[index][i] * ops[i];
        double diff = real_time - expect_time;
        double diff_percent = (diff) * 100 / (expect_time + 1e-6);
        if(expect_time < 1e-6) diff_percent = 0;
        System.out.printf("index %d: expect_time = %f ms, real_time = %f ms, diff = ", index, expect_time, real_time);
        if(Math.abs(diff) < 0.05) System.out.printf("%.2f", diff);
        else if(Math.abs(diff) < 0.1) System.out.printf("\033[1;33;40m%.2f\033[0m", diff);
        else System.out.printf("\033[1;31;40m%.2f\033[0m", diff);
        System.out.print(" ms (");
        if(Math.abs(diff_percent) < 5) System.out.printf("%.2f%%", diff_percent);
        else if(Math.abs(diff_percent) < 10) System.out.printf("\033[1;33;40m%.2f%%\033[0m", diff_percent);
        else System.out.printf("\033[1;31;40m%.2f%%\033[0m", diff_percent);
        System.out.print(")\n");
        return Math.abs(diff_percent) < 10 || Math.abs(diff) < 0.1;
    }
}
