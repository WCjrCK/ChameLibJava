package EllipticCurve.Curve;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;

import java.util.Objects;

public abstract class Curve<G1 extends Point, G2 extends Point, GT extends Point, Zp extends Scalar> {
    private final Config config;
    boolean swap_G1G2;
    protected Curve(Config config) {
        this.config = config;
        if (!config.params.containsKey("swap_G1G2")) this.swap_G1G2 = false;
        else this.swap_G1G2 = (Boolean) config.params.get("swap_G1G2");
    }

    public final CurveName curveName() {
        return config.curveName;
    }

    protected abstract G1 createG1();

    protected abstract G2 createG2();

    protected abstract GT createGT();

    protected abstract Zp createZp();

    protected abstract G1 HashToG1Core(byte[] hash);

    protected abstract G2 HashToG2Core(byte[] hash);

    protected abstract GT HashToGTCore(byte[] hash);

    protected abstract Zp HashToZpCore(byte[] hash);

    protected abstract GT Pairing(G1 p1, G2 p2);

//    protected abstract Point newPoint(CurveGroup group);

    public final Point createPoint(CurveGroup group) {
        Objects.requireNonNull(group, "群类型不能为空");
        Point point;
        switch (group) {
            case G1:
                if (swap_G1G2) point = createG2();
                else point = createG1();
                break;
            case G2:
                if (swap_G1G2) point = createG1();
                else point = createG2();
                break;
            case GT:
                point = createGT();
                break;
            default: throw new IllegalArgumentException("不支持当前群类型： " + group);
        }
        if (point == null) throw new IllegalStateException("Point 实例化失败: 返回值为空");
        if (point.curve() != config.curveName) throw new IllegalStateException("Point 曲线不匹配: 期望 " + config.curveName + " 实际 " + point.curve());
        return point;
    }

    public final Scalar createScalar() {
        return createZp();
    }

    public final Point HashToG1(byte[] hash) {
        if(swap_G1G2) return HashToG2Core(hash);
        else return HashToG1Core(hash);
    }

    public final Point HashToG2(byte[] hash) {
        if(swap_G1G2) return HashToG1Core(hash);
        else return HashToG2Core(hash);
    }

    public final Point HashToGT(byte[] hash) {
        return HashToGT(hash);
    }

    public final Scalar HashToZp(byte[] hash) {
        return HashToZpCore(hash);
    }

    public final GT Pairing(AdditivePoint p1, AdditivePoint p2) {
        if(swap_G1G2) return Pairing((G1) p2, (G2) p1);
        else return Pairing((G1) p1, (G2) p2);
    }

    public final GT Pairing(AdditivePoint p1, MultivePoint p2) {
        if(swap_G1G2) return Pairing((G1) p2, (G2) p1);
        else return Pairing((G1) p1, (G2) p2);
    }

    public final GT Pairing(MultivePoint p1, AdditivePoint p2) {
        if(swap_G1G2) return Pairing((G1) p2, (G2) p1);
        else return Pairing((G1) p1, (G2) p2);
    }

    public final GT Pairing(MultivePoint p1, MultivePoint p2) {
        if(swap_G1G2) return Pairing((G1) p2, (G2) p1);
        else return Pairing((G1) p1, (G2) p2);
    }
}
