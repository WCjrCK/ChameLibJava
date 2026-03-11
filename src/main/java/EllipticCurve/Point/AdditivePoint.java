package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface AdditivePoint {
    AdditivePoint add(AdditivePoint other);

    AdditivePoint sub(AdditivePoint other);

    AdditivePoint mulZn(AdditivePoint scalar);

    AdditivePoint neg();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(AdditivePoint other);
}
