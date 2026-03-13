package PerformTest;

import EllipticCurve.Curve.CurveName;
import PBCTest.BasicParam;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static utils.Func.InitialLib;

@Disabled
public class BasicMemoryTest extends BasicParam {
    @BeforeAll
    static void initTest() {
        InitialLib();
        repeat_cnt = 1000;
    }

    @DisplayName("test PBC memory cost")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource
    void JPBCTest(CurveName curveName) {
//        Curve curve = CurveFactory.create(curveName, PointRepresentation.MULTIVE);
//        Point[] G1List = new Point[repeat_cnt];
//        for (int i = 0; i < repeat_cnt; i++) G1List[i] = curve.createPoint(CurveGroup.G1);
//        jol
//        org.openjdk.jol.info.GraphLayout.parseInstance
//        System.out.println("G1 size: " + (inst.getObjectSize(G1List) / repeat_cnt));
//        Point[] GList = {


//                curve.createPoint(CurveGroup.G1),
//                curve.createPoint(CurveGroup.G2),
//                curve.createPoint(CurveGroup.GT),
//                curve.createPoint(CurveGroup.Zp),
//        };
//        Element[][] Elements = new Element[4][repeat_cnt];
//        for (int i = 0; i < repeat_cnt; i++) for (int j = 0; j < 4; j++) Elements[j][i] = GList[j].newRandomElement().getImmutable();
//        System.out.println(RamUsageEstimator.shallowSizeOf(Elements[0][0]));
//        System.out.println(ClassLayout.parseInstance(Elements[0][0]).toPrintable());
//        System.out.println(Elements[0][0].toBytes());
    }
}
