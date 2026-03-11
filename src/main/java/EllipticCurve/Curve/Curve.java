package EllipticCurve.Curve;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.PointRepresentation;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public abstract class Curve {
    private final CurveName curveName;
    private final GroupRepresentationProfile profile;
    private final Map<String, Object> params;

    protected Curve(CurveName curveName, GroupRepresentationProfile profile) {
        this(curveName, profile, Collections.emptyMap());
    }

    protected Curve(CurveName curveName, GroupRepresentationProfile profile, Map<String, Object> params) {
        this.curveName = Objects.requireNonNull(curveName, "曲线名称不能为空");
        this.profile = Objects.requireNonNull(profile, "群表示配置不能为空");
        this.params = Collections.unmodifiableMap(new LinkedHashMap<>(
                Objects.requireNonNull(params, "曲线参数不能为空")
        ));
    }

    public final CurveName curveName() {
        return curveName;
    }

    public final GroupRepresentationProfile profile() {
        return profile;
    }

    public final PointRepresentation representation(CurveGroup group) {
        return profile.representation(group);
    }

    public final Map<String, Object> params() {
        return params;
    }

    public final Object param(String key) {
        return params.get(key);
    }

    public final Point createPoint(CurveGroup group) {
        Objects.requireNonNull(group, "群类型不能为空");
        if (representation(group) == PointRepresentation.ADDITIVE) return (Point) createAdditivePoint(group);
        return (Point) createMultivePoint(group);
    }

    private final AdditivePoint createAdditivePoint(CurveGroup group) {
        if (representation(group) != PointRepresentation.ADDITIVE) throw new IllegalStateException("当前群被配置为乘法表示: " + group);
        Point point = newPoint(group);
        if (point == null) throw new IllegalStateException("Point 实例化失败: 返回值为空");
        if (point.curve() != curveName) throw new IllegalStateException("Point 曲线不匹配: 期望 " + curveName + " 实际 " + point.curve());
        if (point.group() != group) throw new IllegalStateException("Point 群类型不匹配: 期望 " + group + " 实际 " + point.group());
        if (!(point instanceof AdditivePoint)) throw new IllegalStateException("当前 Point 不支持加法群接口");
        return point;
    }

    private final MultivePoint createMultivePoint(CurveGroup group) {
        if (representation(group) != PointRepresentation.MULTIVE) throw new IllegalStateException("当前群被配置为加法表示: " + group);
        Point point = newPoint(group);
        if (point == null) throw new IllegalStateException("Point 实例化失败: 返回值为空");
        if (point.curve() != curveName) throw new IllegalStateException("Point 曲线不匹配: 期望 " + curveName + " 实际 " + point.curve());
        if (point.group() != group) throw new IllegalStateException("Point 群类型不匹配: 期望 " + group + " 实际 " + point.group());
        if (!(point instanceof MultivePoint)) throw new IllegalStateException("当前 Point 不支持乘法群接口");
        return point;
    }

    protected abstract Point newPoint(CurveGroup group);

    public abstract Point Pairing(Point p1, Point p2);
}
