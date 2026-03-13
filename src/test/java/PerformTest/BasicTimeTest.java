package PerformTest;

import EllipticCurve.Curve.*;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.PointRepresentation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static utils.Func.InitialLib;

@SuppressWarnings("rawtypes")
public class BasicTimeTest extends BasicParam {
    static CurveGroup[] idxgroup = {CurveGroup.G1, CurveGroup.G2, CurveGroup.GT, CurveGroup.Zp};

    @BeforeAll
    static void initTest() {
        repeat_cnt = 10000;
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter(String.format("./data/Basic_Time_%d.csv", repeat_cnt)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test operation time cost")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource
    void TimeTest(CurveName curveName) {
        Config config = new Config(curveName, PointRepresentation.MULTIVE);
        if (index_map.getOrDefault(curveName, -1) == -1) return;
        int index = index_map.get(curveName);
        Curve curve = CurveFactory.create(config);
        Point[][] Points = new Point[4][repeat_cnt + 1];


        for (int i = 0; i <= repeat_cnt; i++) {
            Points[0][i] = curve.createPoint(CurveGroup.G1);
            Points[1][i] = curve.createPoint(CurveGroup.G2);
            Points[2][i] = curve.createPoint(CurveGroup.GT);
            Points[3][i] = curve.createPoint(CurveGroup.Zp);
        }
        int op_time_id = -1;

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) curve.createPoint(idxgroup[i_]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Points[i_][i].mul(Points[i_][i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Points[i_][i].pow(Points[3][i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) curve.Pairing(Points[0][i], Points[1][i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
    }

    @AfterAll
    static void finishTest() {
        try {
            File_Writer.write("curve,");
            for (int i_ = 0; i_ < 4; i_++) File_Writer.write(String.format("R in %s,", idxgroup[i_].name()));
            for (int i_ = 0; i_ < 4; i_++) File_Writer.write(String.format("Add in %s,", idxgroup[i_].name()));
            for (int i_ = 0; i_ < 4; i_++) File_Writer.write(String.format("Pow in %s,", idxgroup[i_].name()));
            File_Writer.write("Pairing\n");
            for(CurveName curve : CurveName.values()) {
                if (index_map.getOrDefault(curve, -1) == -1) continue;
                File_Writer.write(String.format("%s", curve));
                int i = index_map.get(curve);
                for (int j = 0; j < op_time[i].length; j++) File_Writer.write(String.format(",%.6f", op_time[i][j]));
                File_Writer.write("\n");
            }
            System.out.println("{");
            for (int i = 0; i < op_time.length; i++) {
                if(i != 0) System.out.print(",\n");
                System.out.print("    {");
                for (int j = 0; j < op_time[i].length; j++) {
                    if(j != 0) System.out.print(", ");
                    System.out.printf("%.6f", op_time[i][j]);
                }
                System.out.print("}");
            }
            System.out.println("\n}");
            File_Writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
