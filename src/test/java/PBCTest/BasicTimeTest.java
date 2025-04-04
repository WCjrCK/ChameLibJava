package PBCTest;

import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import utils.Hash;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import static utils.Func.InitialLib;
import static utils.Func.PairingGen;

@SuppressWarnings("rawtypes")
public class BasicTimeTest extends BasicParam {

    @BeforeAll
    static void initTest() {
        InitialLib();
        try {
            File_Writer = new BufferedWriter(new FileWriter("./data/PBC/Basic_Time.txt"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("test PBC operation time cost")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(PBC.class)
    void JPBCTest(PBC curve) {
        int index = index_map.get(curve);
        var pairing = PairingGen(curve);
        Field[] GList = {pairing.getG1(), pairing.getG2(), pairing.getGT(), pairing.getZr()};
        Element[][] Elements = new Element[4][repeat_cnt + 1];
        for (int i = 0; i <= repeat_cnt; i++) for (int j = 0; j < 4; j++) Elements[j][i] = GList[j].newRandomElement().getImmutable();
        int op_time_id = -1;

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) GList[i_].newRandomElement();
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Hash.H_PBC_1_1(GList[i_], Elements[i_][i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Elements[i_][i].mul(Elements[i_][i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        for (int i_ = 0; i_ < 4; i_++) {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Elements[i_][i].powZn(Elements[3][i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) pairing.pairing(Elements[0][i], Elements[1][i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
    }

    @AfterAll
    static void finishTest() {
        try {
            for (PBC curve : index_map.keySet()) {
                File_Writer.write(String.format("curve:%s: ", curve));
                int i = index_map.get(curve);
                for (int j = 0; j < op_time[i].length; j++) File_Writer.write(String.format("%.6f, ", op_time[i][j]));
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
