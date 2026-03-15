package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

import java.util.Objects;

public abstract class Scalar<S extends Scalar<S>> {
    protected final CurveName curve;
    protected final CurveGroup group = CurveGroup.Zp;
    protected Scalar(CurveName curve) {
        this.curve = Objects.requireNonNull(curve, "曲线不能为空");
    }

    protected abstract S addCore(S other);

    protected abstract S subCore(S other);

    protected abstract S mulCore(S scalar);

    protected abstract S divCore(S scalar);

    protected abstract S negCore();

    public abstract S inv();

    public abstract String toString();

    public abstract S copy();

    public abstract boolean isEqual(S other);

    public final S add(S other) {
        return addCore(other);
    }

    public final S sub(S other) {
        return subCore(other);
    }

    public final S mul(S scalar) {
        return mulCore(scalar);
    }

    public final S div(S scalar) {
        return divCore(scalar);
    }

    public final S neg() {
        return negCore();
    }

    public abstract boolean isOne();

    public abstract boolean isZero();

    public final CurveName curve() {
        return curve;
    }

    public final CurveGroup group() {
        return group;
    }
}
