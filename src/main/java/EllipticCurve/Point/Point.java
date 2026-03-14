package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

import java.math.BigInteger;
import java.util.Objects;

public abstract class Point<P extends Point<P, S>, S extends Scalar<S>>
        implements AdditivePoint<P, S>, MultivePoint<P, S> {
    protected final CurveName curve;
    protected final CurveGroup group;

    protected Point(CurveName curve, CurveGroup group) {
        this.curve = Objects.requireNonNull(curve, "曲线不能为空");
        this.group = Objects.requireNonNull(group, "群类型不能为空");
    }

    protected Point(CurveName curve) {
        this(curve, CurveGroup.G1);
    }

    protected abstract P addCore(P other);

    protected abstract P subCore(P other);

    protected abstract P mulCore(S scalar);

    protected abstract P divCore(S scalar);

    protected abstract P negCore();

    public abstract BigInteger toBigInteger();

    public abstract String toString();

    public abstract boolean isEqual(P other);

    public abstract P copy();

    // public abstract boolean isInfinity();

    public abstract byte[] toBytes();

    @Override
    public final CurveName curve() {
        return curve;
    }

    @Override
    public final CurveGroup group() {
        return group;
    }

    @Override
    public final AdditivePoint<P, S> add(AdditivePoint<P, S> other) {
        requireSameCurve((P) other);
        return addCore((P) other);
    }

    @Override
    public final AdditivePoint<P, S> sub(AdditivePoint<P, S> other) {
        requireSameCurve((P) other);
        return subCore((P) other);
    }

    @Override
    public final P mul(S scalar) {
        return mulCore(requireScalar(scalar, "标量"));
    }

    @Override
    public final P div(S scalar) {
        return divCore(requireScalar(scalar, "标量"));
    }

    @Override
    public final P neg() {
        return negCore();
    }

    @Override
    public final MultivePoint<P, S> mul(MultivePoint<P, S> other) {
        requireSameCurve((P) other);
        return addCore((P) other);
    }

    @Override
    public final MultivePoint<P, S> div(MultivePoint<P, S> other) {
        requireSameCurve((P) other);
        return subCore((P) other);
    }

    @Override
    public final boolean isEqual(AdditivePoint<P, S> other) {
        return isEqual((P) other);
    }

    @Override
    public final boolean isEqual(MultivePoint<P, S> other) {
        return isEqual((P) other);
    }

    @Override
    public final P pow(S exponent) {
        return mulCore(requireScalar(exponent, "标量"));
    }

    @Override
    public final P ext(S exponent) {
        return divCore(requireScalar(exponent, "标量"));
    }

    @Override
    public final P inv() {
        return negCore();
    }

    protected final void requireSameCurve(P other) {
        Objects.requireNonNull(other, "点不能为空");
        if (curve != other.curve || group != other.group) {
            throw new IllegalArgumentException(
                    "点不在同一曲线群中: " + curve + "/" + group + " 与 " + other.curve + "/" + other.group
            );
        }
    }

    protected final S requireScalar(S scalar, String name) {
        if (scalar == null || scalar.group() != CurveGroup.Zp) throw new IllegalArgumentException(name + " 不能为空");
        return scalar;
    }
}
