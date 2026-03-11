package EllipticCurve.Point;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;

import java.math.BigInteger;
import java.util.Arrays;
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

    public final CurveName curve() {
        return curve;
    }

    public final CurveGroup group() {
        return group;
    }

    protected abstract Point addCore(Point other);

    protected abstract Point subCore(Point other);

    protected abstract Point mulCore(BigInteger scalar);

    protected abstract Point negCore();

    // public abstract Point copy();

    // public abstract boolean isInfinity();

    public abstract byte[] toBytes();

    @Override
    public final Point add(Point other) {
        requireSameCurve(other);
        return addCore(other);
    }

    @Override
    public final Point sub(Point other) {
        requireSameCurve(other);
        return subCore(other);
    }

    @Override
    public final Point mul(BigInteger scalar) {
        return mulCore(requireScalar(scalar, "标量"));
    }

    @Override
    public final Point neg() {
        return negCore();
    }

    @Override
    public final Point mul(Point other) {
        return add(other);
    }

    @Override
    public final Point div(Point other) {
        return sub(other);
    }

    @Override
    public final Point pow(BigInteger exponent) {
        return mul(exponent);
    }

    @Override
    public final Point inv() {
        return neg();
    }

    public final boolean sameValue(Point other) {
        Objects.requireNonNull(other, "点不能为空");
        return Arrays.equals(toBytes(), other.toBytes());
    }

    protected final void requireSameCurve(Point other) {
        Objects.requireNonNull(other, "点不能为空");
        if (curve != other.curve || group != other.group) {
            throw new IllegalArgumentException(
                    "点不在同一曲线群中: " + curve + "/" + group + " 与 " + other.curve + "/" + other.group
            );
        }
    }

    protected final BigInteger requireScalar(BigInteger scalar, String name) {
        if (scalar == null) throw new IllegalArgumentException(name + " 不能为空");
        return scalar;
    }
}
