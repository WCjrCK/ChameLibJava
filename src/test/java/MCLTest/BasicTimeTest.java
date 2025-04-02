package MCLTest;

import com.herumi.mcl.*;
import curve.MCL;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import utils.Func;
import utils.Hash;

import static utils.Func.InitialLib;

public class BasicTimeTest extends BasicParam {
    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test MCL operation time cost")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(names = {"BN254", "BLS12_381"})
    void MCLTest(MCL curve) {
        Func.MCLInit(curve);
        int index = index_map.get(curve);
        G1[] G1List = new G1[repeat_cnt + 1];
        G2[] G2List = new G2[repeat_cnt + 1];
        GT[] GTList = new GT[repeat_cnt + 1];
        Fr[] FrList = new Fr[repeat_cnt + 1];

        for (int i = 0; i <= repeat_cnt; i++) {
            G1List[i] = new G1();
            G2List[i] = new G2();
            FrList[i] = new Fr();
            GTList[i] = new GT();
        }

        int op_time_id = -1;
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Func.GetMCLG1RandomElement(G1List[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Func.GetMCLG2RandomElement(G2List[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Func.GetMCLGTRandomElement(GTList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Func.GetMCLZrRandomElement(FrList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Hash.H_MCL_G1_1(G1List[i], String.valueOf(i));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Hash.H_MCL_G2_1(G2List[i], String.valueOf(i));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Hash.H_MCL_GT_1(GTList[i], String.valueOf(i));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Hash.H_MCL_Zr_1(FrList[i], String.valueOf(i));
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.add(G1List[i], G1List[i], G1List[i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.add(G2List[i], G2List[i], G2List[i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.mul(GTList[i], GTList[i], GTList[i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.mul(FrList[i], FrList[i], FrList[i + 1]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.mul(G1List[i], G1List[i], FrList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.mul(G2List[i], G2List[i], FrList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.pow(GTList[i], GTList[i], FrList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.mul(FrList[i], FrList[i], FrList[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }

        {
            long start = System.nanoTime();
            for(int i = 0;i < repeat_cnt;++i) Mcl.pairing(GTList[i], G1List[i], G2List[i]);
            long end = System.nanoTime();
            double duration = (end - start) / 1.0e6;
            op_time[index][++op_time_id] = duration / repeat_cnt;
        }
    }

    @AfterAll
    static void finishTest() {
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
    }
}
