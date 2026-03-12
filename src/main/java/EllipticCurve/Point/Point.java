package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

import java.math.BigInteger;
import java.util.Objects;

public abstract class Point implements AdditivePoint, MultivePoint {
    private final CurveName curve;
    private final CurveGroup group;

    protected Point(CurveName curve, CurveGroup group) {
        this.curve = Objects.requireNonNull(curve, "曲线不能为空");
        this.group = Objects.requireNonNull(group, "群类型不能为空");
    }

    protected Point(CurveName curve) {
        this(curve, CurveGroup.G1);
    }

    protected abstract Point addCore(Point other);

    protected abstract Point subCore(Point other);

    protected abstract Point mulCore(AdditivePoint scalar);

    protected abstract Point negCore();

    public abstract BigInteger toBigInteger();

    public abstract String toString();

    public abstract boolean isEqual(Point other);

    public abstract AdditivePoint invZn();

    // public abstract Point copy();

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
    public final AdditivePoint add(AdditivePoint other) {
        requireSameCurve((Point) other);
        return addCore((Point) other);
    }

    @Override
    public final AdditivePoint sub(AdditivePoint other) {
        requireSameCurve((Point) other);
        return subCore((Point) other);
    }

    @Override
    public final AdditivePoint mulZn(AdditivePoint scalar) {
        return mulCore(requireScalar(scalar, "标量"));
    }

    @Override
    public final AdditivePoint neg() {
        return negCore();
    }

    @Override
    public final MultivePoint mul(MultivePoint other) {
        requireSameCurve((Point) other);
        return addCore((Point) other);
    }

    @Override
    public final MultivePoint div(MultivePoint other) {
        requireSameCurve((Point) other);
        return subCore((Point) other);
    }

    @Override
    public final MultivePoint pow(AdditivePoint exponent) {
        return mulCore(requireScalar(exponent, "标量"));
    }

    @Override
    public final MultivePoint inv() {
        return negCore();
    }

    @Override
    public final boolean isEqual(AdditivePoint other) {
        return isEqual((Point) other);
    }

    @Override
    public final boolean isEqual(MultivePoint other) {
        return isEqual((Point) other);
    }

    protected final void requireSameCurve(Point other) {
        Objects.requireNonNull(other, "点不能为空");
        if (curve != other.curve || group != other.group) {
            throw new IllegalArgumentException(
                    "点不在同一曲线群中: " + curve + "/" + group + " 与 " + other.curve + "/" + other.group
            );
        }
    }

    protected final AdditivePoint requireScalar(AdditivePoint scalar, String name) {
        if (scalar == null || scalar.group() != CurveGroup.Zp) throw new IllegalArgumentException(name + " 不能为空");
        return scalar;
    }
}
