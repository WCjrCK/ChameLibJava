package EllipticCurve.Point;

import java.math.BigInteger;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface MultivePoint {
    MultivePoint mul(MultivePoint other);

    MultivePoint div(MultivePoint other);

    MultivePoint pow(BigInteger exponent);

    MultivePoint inv();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(MultivePoint other);
}
