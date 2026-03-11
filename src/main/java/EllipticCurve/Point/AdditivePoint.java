package EllipticCurve.Point;

import java.math.BigInteger;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface AdditivePoint {
    AdditivePoint add(AdditivePoint other);

    AdditivePoint sub(AdditivePoint other);

    AdditivePoint mul(BigInteger scalar);

    AdditivePoint neg();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(AdditivePoint other);
}
