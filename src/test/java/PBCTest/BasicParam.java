package PBCTest;

import curve.Group;
import curve.PBC;
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
            {0.576208, 0.573114, 0.069271, 0.007884, 1.324570, 1.331779, 0.068649, 0.006407, 0.007179, 0.007193, 0.004813, 0.003680, 0.603068, 0.594750, 0.051539, 0.006585, 0.348226},
            {0.393965, 0.308085, 0.034659, 0.008537, 0.294812, 0.297922, 0.028663, 0.007405, 0.010259, 0.010636, 0.005035, 0.004464, 7.434316, 7.330835, 0.600688, 0.158567, 7.268347},
            {0.226205, 2.025189, 0.255119, 0.034721, 0.024063, 5.652678, 0.231923, 0.004929, 0.004971, 0.014122, 0.006631, 0.003652, 0.215647, 1.989944, 0.468916, 0.006511, 1.580485},
            {0.305679, 2.365844, 0.327311, 0.007537, 0.052814, 6.982258, 0.289361, 0.004585, 0.005068, 0.013737, 0.006527, 0.003577, 0.298786, 2.362341, 0.516422, 0.006501, 1.856614},
            {0.375859, 2.976391, 0.325710, 0.007577, 0.047512, 8.121043, 0.290328, 0.005490, 0.005430, 0.014717, 0.006534, 0.003511, 0.376640, 2.812664, 0.586075, 0.008096, 2.072145},
            {0.300216, 2.379536, 0.300604, 0.007618, 0.050012, 6.594692, 0.285730, 0.005053, 0.005484, 0.015636, 0.006741, 0.003523, 0.314715, 2.489424, 0.532628, 0.006860, 1.853792},
            {0.251609, 2.163745, 0.279981, 0.007572, 0.031461, 5.538606, 0.240293, 0.004724, 0.004863, 0.013081, 0.006536, 0.003339, 0.227258, 1.981251, 0.464861, 0.019878, 1.556090},
            {0.322092, 2.410617, 0.366034, 0.007428, 0.051849, 6.340813, 0.270633, 0.005653, 0.005342, 0.015435, 0.006884, 0.003635, 0.297014, 2.409334, 0.570972, 0.008403, 1.984686},
            {1.168492, 1.171653, 0.139047, 0.008050, 5.443918, 5.327919, 0.129822, 0.004560, 0.009012, 0.009013, 0.003773, 0.003209, 1.108055, 1.106570, 0.029871, 0.005875, 0.984457},
            {0.211737, 0.418391, 5.134802, 0.008162, 0.010823, 0.029631, 5.141156, 0.005001, 0.006119, 0.007685, 0.017144, 0.004119, 0.213752, 0.432450, 1.770388, 0.006084, 7.495501},
            {0.523323, 0.857824, 8.509257, 0.007867, 0.020677, 0.039397, 8.399914, 0.004787, 0.005934, 0.007368, 0.014929, 0.003685, 0.486429, 0.842521, 2.870223, 0.009228, 12.840274},
            {0.198158, 3.808206, 1.761870, 0.007632, 0.012184, 25.240315, 1.759762, 0.005045, 0.005292, 0.024315, 0.013361, 0.004054, 0.199912, 3.819947, 1.282438, 0.005926, 4.593954}
    };

    static public HashMap<PBC, Integer> index_map = new HashMap<>() {{
        put(PBC.A, 0);
        put(PBC.A1, 1);
        put(PBC.D_159, 2);
        put(PBC.D_201, 3);
        put(PBC.D_224, 4);
        put(PBC.D_105171_196_185, 5);
        put(PBC.D_277699_175_167, 6);
        put(PBC.D_278027_190_181, 7);
        put(PBC.E, 8);
        put(PBC.F, 9);
        put(PBC.SM_9, 10);
        put(PBC.G_149, 11);
    }};

    static public List<Integer> BT_leaf_num = List.of(2048, 4096, 8192);
    static public List<Integer> IdentityLen = List.of(64, 128, 256);
    static public List<Integer> RSA_bit_len = List.of(256, 512, 1024);
    static public List<Integer> RSA_bit_len_small = List.of(64, 128, 256);
    static public List<Integer> Auth_num = List.of(256, 512, 1024);

    public static Stream<Arguments> GetPBCCartesianProduct() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                EnumSet.allOf(Group.class).stream().flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

    public static Stream<Arguments> GetPBCInvert() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(Arguments.of(a, false), Arguments.of(a, true))
        );
    }

    public static Stream<Arguments> GetPBCSymmetry() {
        return Stream.of(Arguments.of(PBC.A), Arguments.of(PBC.A1), Arguments.of(PBC.E));
    }

    public static Stream<Arguments> GetPBCInvertIdentityLen() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                IdentityLen.stream().flatMap(b ->
                        Stream.of(Arguments.of(a, b, false), Arguments.of(a, b, true))
                )
        );
    }

    public static Stream<Arguments> GetPBCInvertk() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                RSA_bit_len.stream().flatMap(b ->
                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
                )
        );
    }

    public static Stream<Arguments> GetPBCSymmAuth() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Auth_num.stream().flatMap(b ->
                        RSA_bit_len.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    public static Stream<Arguments> GetPBCSymmAuthSmall() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Auth_num.stream().flatMap(b ->
                        RSA_bit_len_small.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    public static Stream<Arguments> GetPBCSymmAuthBigLambda() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Auth_num.stream().flatMap(b ->
                        RSA_bit_len.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    public static Stream<Arguments> GetPBCInvertkn() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                RSA_bit_len.stream().flatMap(b ->
                        BT_leaf_num.stream().flatMap(c ->
                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
                        )
                )
        );
    }

    public static Stream<Arguments> GetPBCInvertGroupn() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                EnumSet.allOf(Group.class).stream().flatMap(b ->
                        BT_leaf_num.stream().flatMap(c ->
                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
                        )
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
