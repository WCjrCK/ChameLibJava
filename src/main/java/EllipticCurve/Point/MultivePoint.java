package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface MultivePoint {
    MultivePoint mul(MultivePoint other);

    MultivePoint div(MultivePoint other);

    MultivePoint pow(AdditivePoint exponent);

    MultivePoint inv();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(MultivePoint other);
}
