package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

public interface AdditivePoint<P extends Point<P, S>, S extends Scalar<S>> {
    AdditivePoint<P, S> add(AdditivePoint<P, S> other);

    AdditivePoint<P, S> sub(AdditivePoint<P, S> other);

    AdditivePoint<P, S> mul(S scalar);

    AdditivePoint<P, S> div(S scalar);

    AdditivePoint<P, S> neg();

    CurveGroup group();

    CurveName curve();

    String toString();

    boolean isEqual(AdditivePoint<P, S> other);

    AdditivePoint<P, S> copy();

    byte[] toBytes();
}
