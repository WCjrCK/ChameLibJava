package UnitTest;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.PointRepresentation;

import static org.junit.jupiter.api.Assertions.*;
import static utils.Func.InitialLib;

public class EllipticCurveTest {
    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test elliptic curve")
    @Nested
    class ECTest {
        @DisplayName("示例1: 按曲线+表示配置+群类型创建 Point")
        @Test
        void createPointByCurveAndGroup() {
            Curve curve = CurveFactory.create(CurveName.A, PointRepresentation.MULTIVE);
            AdditivePoint g1 = curve.createPoint(CurveGroup.G1);
            AdditivePoint g1_t = curve.createPoint(CurveGroup.G1);
            AdditivePoint g2 = curve.createPoint(CurveGroup.G2);
            MultivePoint gt = curve.createPoint(CurveGroup.GT);
            MultivePoint gt_t = curve.createPoint(CurveGroup.GT);

            assertNotNull(g1);
            assertNotNull(g2);
            assertNotNull(gt);
            assertEquals(CurveName.A, g1.curve());
            assertEquals(CurveGroup.G1, g1.group());
            assertEquals(CurveGroup.G2, g2.group());
            assertEquals(CurveGroup.GT, gt.group());

            g1_t = g1.add(g1_t);
            gt = curve.Pairing(g1, g2);
            gt_t = gt.mul(gt_t);

            curve = CurveFactory.create(CurveName.BN254, PointRepresentation.MULTIVE);
            g1 = curve.createPoint(CurveGroup.G1);
            g1_t = curve.createPoint(CurveGroup.G1);
            g2 = curve.createPoint(CurveGroup.G2);
            gt = curve.createPoint(CurveGroup.GT);

            g1_t = g1.add(g1_t);
            gt = curve.Pairing(g1, g2);
        }

        // @DisplayName("示例3: 等号赋值 vs copy()")
        // @Test
        // void assignmentAndCopyExample() {
        //     Curve curve = CurveFactory.create(CurveName.SECP256K1, 0); // 0 => G1/G2/GT 全是加法表示
        //     Point p1 = curve.createPoint(CurveGroup.G1);

        //     Point alias = p1;      // 仅复制引用
        //     Point copied = p1.copy(); // 新对象（由实现类决定深拷贝内容）

        //     assertSame(p1, alias, "等号赋值只是引用别名（浅拷贝语义）");
        //     assertNotSame(p1, copied, "copy() 应返回新对象");
        //     assertEquals(p1.curve(), copied.curve());
        //     assertEquals(p1.group(), copied.group());
        // }

//        @DisplayName("示例4: 运算函数调用方式（当前默认实现未接算法）")
//        @Test
//        void operationCallStyleExample() {
//            Curve curve = CurveFactory.createUniform(CurveName.BN254, PointRepresentation.ADDITIVE);
//            Point p1 = curve.createPoint(CurveGroup.G1);
//            Point p2 = curve.createPoint(CurveGroup.G1);
//
//            assertThrows(UnsupportedOperationException.class, () -> p1.add(p2));
//            assertThrows(UnsupportedOperationException.class, () -> p1.sub(p2));
//            assertThrows(UnsupportedOperationException.class, () -> p1.mul(BigInteger.ONE));
//            assertThrows(UnsupportedOperationException.class, p1::neg);
//            assertThrows(UnsupportedOperationException.class, () -> p1.mul(p2));
//            assertThrows(UnsupportedOperationException.class, () -> p1.div(p2));
//            assertThrows(UnsupportedOperationException.class, () -> p1.pow(BigInteger.ONE));
//            assertThrows(UnsupportedOperationException.class, p1::inv);
//        }
    }
}
