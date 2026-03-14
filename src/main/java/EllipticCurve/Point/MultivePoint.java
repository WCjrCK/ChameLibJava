package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface MultivePoint<P extends Point<P, S>, S extends Scalar<S>> {
    MultivePoint<P, S> mul(MultivePoint<P, S> other);

    MultivePoint<P, S> div(MultivePoint<P, S> other);

    MultivePoint<P, S> pow(S exponent);

    MultivePoint<P, S> ext(S exponent);

    MultivePoint<P, S> inv();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(MultivePoint<P, S> other);

    MultivePoint<P, S> copy();
}
