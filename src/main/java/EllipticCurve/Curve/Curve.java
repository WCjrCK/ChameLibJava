package EllipticCurve.Curve;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.PointRepresentation;

import java.util.Objects;

public abstract class Curve {
    private final Config config;
    protected Curve(Config config) {
        this.config = config;
    }

    public final CurveName curveName() {
        return config.curveName;
    }

    public final PointRepresentation representation(CurveGroup group) {
        switch (group) {
            case G1: return config.G1r;
            case G2: return config.G2r;
            case GT: return config.GTr;
            case Zp: return PointRepresentation.ADDITIVE;
        }
        throw new IllegalArgumentException("尚未支持当前群：" + group);
    }

    public final Point createPoint(CurveGroup group) {
        Objects.requireNonNull(group, "群类型不能为空");
        if (group == CurveGroup.Zp) return (Point) createAdditivePoint(group);
        if (representation(group) == PointRepresentation.ADDITIVE) return (Point) createAdditivePoint(group);
        return (Point) createMultivePoint(group);
    }

    private AdditivePoint createAdditivePoint(CurveGroup group) {
        if (representation(group) != PointRepresentation.ADDITIVE) throw new IllegalStateException("当前群被配置为乘法表示: " + group);
        Point point = newPoint(group);
        if (point == null) throw new IllegalStateException("Point 实例化失败: 返回值为空");
        if (point.curve() != config.curveName) throw new IllegalStateException("Point 曲线不匹配: 期望 " + config.curveName + " 实际 " + point.curve());
        return point;
    }

    private MultivePoint createMultivePoint(CurveGroup group) {
        if (representation(group) != PointRepresentation.MULTIVE) throw new IllegalStateException("当前群被配置为加法表示: " + group);
        Point point = newPoint(group);
        if (point == null) throw new IllegalStateException("Point 实例化失败: 返回值为空");
        if (point.curve() != config.curveName) throw new IllegalStateException("Point 曲线不匹配: 期望 " + config.curveName + " 实际 " + point.curve());
        return point;
    }

    protected abstract Point newPoint(CurveGroup group);

    public abstract Point Pairing(Point p1, Point p2);

    public abstract Point HashToG1(byte[] hash);

    public abstract Point HashToG2(byte[] hash);

    public abstract Point HashToGT(byte[] hash);

    public abstract Point HashToZp(byte[] hash);

    public final Point Pairing(AdditivePoint p1, AdditivePoint p2) {
        return Pairing((Point) p1, (Point) p2);
    }

    public final Point Pairing(AdditivePoint p1, MultivePoint p2) {
        return Pairing((Point) p1, (Point) p2);
    }

    public final Point Pairing(MultivePoint p1, AdditivePoint p2) {
        return Pairing((Point) p1, (Point) p2);
    }

    public final Point Pairing(MultivePoint p1, MultivePoint p2) {
        return Pairing((Point) p1, (Point) p2);
    }
}
