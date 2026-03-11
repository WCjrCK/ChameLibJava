package EllipticCurve.Point.implement.MCLPoint;

import java.math.BigInteger;

import com.herumi.mcl.Mcl;
import com.herumi.mcl.Fr;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;

public class MCLPointZp extends Point {
    public Fr p;

    public MCLPointZp(Fr p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final MCLPointZp addCore(Point other) {
        if (!(other instanceof MCLPointZp)) throw new IllegalArgumentException("不支持的点类型");
        Fr result = new Fr();
        Mcl.add(result, p, ((MCLPointZp) other).p);
        return new MCLPointZp(result, curve(), group());
    }

    @Override
    protected final MCLPointZp subCore(Point other) {
        if (!(other instanceof MCLPointZp)) throw new IllegalArgumentException("不支持的点类型");
        Fr result = new Fr();
        Mcl.sub(result, p, ((MCLPointZp) other).p);
        return new MCLPointZp(result, curve(), group());
    }

    @Override
    protected final MCLPointZp mulCore(BigInteger scalar) {
        Fr result = new Fr();
        Mcl.mul(result, p, new Fr(scalar.toString()));
        return new MCLPointZp(result, curve(), group());
    }

    @Override
    protected final MCLPointZp negCore() {
        Fr result = new Fr();
        Mcl.neg(result, p);
        return new MCLPointZp(result, curve(), group());
    }

    // @Override
    // public final MCLPointZp copy() {
    //     return new MCLPointZp(p.(), curve(), group());
    // }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }
}
