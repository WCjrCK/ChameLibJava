package PerformTest;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import org.junit.jupiter.params.provider.Arguments;

import java.io.BufferedWriter;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

@SuppressWarnings("unused")
public class BasicParam {
    static public BufferedWriter File_Writer;
    static public BufferedWriter real_time_cost;
    static public BufferedWriter theo_time_cost;
    static Random RAND = new Random();
    static public int diff_max_len = 17, repeat_cnt = 1000;

    static public double[][] op_time = {
            {0.600586, 0.631503, 0.079281, 0.012406, 0.009631, 0.013065, 0.006211, 0.003880, 0.557920, 0.552783, 0.046825, 0.003819, 0.328698},
            {0.299224, 0.296043, 0.041835, 0.010575, 0.010443, 0.010275, 0.004945, 0.004075, 7.519040, 7.673912, 0.652768, 0.004557, 7.836959},
            {1.216191, 1.198572, 0.146566, 0.010618, 0.010132, 0.009637, 0.004181, 0.005896, 1.207691, 1.187645, 0.031167, 0.004112, 1.086492},
            {0.244092, 2.781848, 0.289914, 0.010286, 0.006480, 0.018355, 0.008392, 0.004119, 0.237927, 2.015134, 0.485380, 0.004838, 1.601912},
            {0.322520, 3.543157, 0.385363, 0.010394, 0.005684, 0.015879, 0.008981, 0.004718, 0.310285, 2.558733, 0.554459, 0.005542, 1.893763},
            {0.444154, 3.219620, 0.342156, 0.010011, 0.007982, 0.019454, 0.009935, 0.004532, 0.383880, 3.175790, 0.661095, 0.005556, 2.390036},
            {0.324926, 2.779254, 0.350521, 0.010109, 0.005662, 0.015853, 0.007729, 0.003684, 0.304339, 2.679157, 0.586524, 0.004617, 2.043067},
            {0.260687, 2.229773, 0.309177, 0.010259, 0.005947, 0.015689, 0.007275, 0.005117, 0.248182, 2.259557, 0.506710, 0.005748, 1.672521},
            {0.326711, 2.752839, 0.335143, 0.010318, 0.007587, 0.020904, 0.010340, 0.006357, 0.313031, 2.494733, 0.559893, 0.004677, 1.938202},
            {0.252538, 0.448383, 5.494783, 0.010207, 0.005641, 0.007061, 0.015670, 0.006804, 0.233699, 0.457260, 1.833299, 0.007275, 8.020021},
            {0.509237, 0.981672, 10.434925, 0.010437, 0.006200, 0.007579, 0.024454, 0.004766, 0.509245, 0.917641, 3.249352, 0.005211, 15.756704},
            {0.218432, 17.837764, 5.458206, 0.011637, 0.005793, 0.025253, 0.013915, 0.005975, 0.235479, 4.180943, 1.376791, 0.004929, 5.022501},
            {0.018182, 0.042000, 0.202145, 0.001008, 0.000592, 0.000868, 0.001020, 0.000340, 0.024997, 0.039631, 0.070073, 0.001674, 0.144821},
            {0.072976, 0.123844, 0.575752, 0.000958, 0.000635, 0.001293, 0.001471, 0.000224, 0.043155, 0.073663, 0.116226, 0.000831, 0.368496}
    };

    static public HashMap<CurveName, Integer> index_map = new HashMap<>() {};
    static {
        int i = 0;
        for (CurveName e : CurveName.values()) {
            if (e == CurveName.PBC_CUSTOM || e == CurveName.SECP256K1) continue;
            index_map.put(e, i);
            i += 1;
        }
    }

    static public List<Integer> BT_leaf_num = List.of(1024, 2048, 4096);
    static public List<Integer> IdentityLen = List.of(32, 64, 128);
    static public List<Integer> RSA_bit_len = List.of(256, 512, 1024);
    static public List<Integer> RSA_bit_len_small = List.of(32, 64, 128);
    static public List<Integer> Auth_num = List.of(256, 512, 1024);

    public static Stream<Arguments> GetCartesianProduct() {
        return EnumSet.allOf(CurveName.class).stream().flatMap(a ->
                EnumSet.allOf(CurveGroup.class).stream().flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

//    public static Stream<Arguments> GetSchemeCurveEnum() {
//        return EnumSet.allOf(SchemeName.class).stream().flatMap(a ->
//                EnumSet.allOf(CurveName.class).stream().flatMap(b ->
//                        Stream.of(Arguments.of(a, b))
//                )
//        );
//    }

//    public static Stream<Arguments> GetPBCInvert() {
//        return EnumSet.allOf(PBC.class).stream().flatMap(a ->
//                Stream.of(Arguments.of(a, false), Arguments.of(a, true))
//        );
//    }
//
//    public static Stream<Arguments> GetPBCSymmetry() {
//        return Stream.of(Arguments.of(PBC.A), Arguments.of(PBC.A1), Arguments.of(PBC.E));
//    }
//
//    public static Stream<Arguments> GetPBCInvertIdentityLen() {
//        return EnumSet.allOf(PBC.class).stream().flatMap(a ->
//                IdentityLen.stream().flatMap(b ->
//                        Stream.of(Arguments.of(a, b, false), Arguments.of(a, b, true))
//                )
//        );
//    }
//
//    public static Stream<Arguments> GetPBCInvertk() {
//        return EnumSet.allOf(PBC.class).stream().flatMap(a ->
//                RSA_bit_len.stream().flatMap(b ->
//                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
//                )
//        );
//    }
//
//    public static Stream<Arguments> GetPBCSymmAuth() {
//        return Stream.of(PBC.A, PBC.A1, PBC.E).flatMap(a ->
//                Auth_num.stream().flatMap(b ->
//                        RSA_bit_len.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
//    }
//
//    public static Stream<Arguments> GetPBCSymmAuthSmall() {
//        return Stream.of(PBC.A, PBC.A1, PBC.E).flatMap(a ->
//                Auth_num.stream().flatMap(b ->
//                        RSA_bit_len_small.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
//    }
//
//    public static Stream<Arguments> GetPBCSymmAuthBigLambda() {
//        return Stream.of(PBC.A, PBC.A1, PBC.E).flatMap(a ->
//                Auth_num.stream().flatMap(b ->
//                        RSA_bit_len.stream().flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
//    }
//
//    public static Stream<Arguments> GetPBCInvertkn() {
//        return EnumSet.allOf(PBC.class).stream().flatMap(a ->
//                RSA_bit_len.stream().flatMap(b ->
//                        BT_leaf_num.stream().flatMap(c ->
//                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
//                        )
//                )
//        );
//    }
//
//    public static Stream<Arguments> GetPBCInvertGroupn() {
//        return EnumSet.allOf(PBC.class).stream().flatMap(a ->
//                EnumSet.allOf(Group.class).stream().flatMap(b ->
//                        BT_leaf_num.stream().flatMap(c ->
//                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
//                        )
//                )
//        );
//    }

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
