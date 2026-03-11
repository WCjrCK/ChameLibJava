package EllipticCurve.Point.implement.MCLPoint;

import java.math.BigInteger;

import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;
import com.herumi.mcl.GT;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;

public class MCLPointGT extends Point {
    public GT p;

    public MCLPointGT(GT p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final MCLPointGT addCore(Point other) {
        if (!(other instanceof MCLPointGT)) throw new IllegalArgumentException("不支持的点类型");
        GT result = new GT();
        Mcl.mul(result, p, ((MCLPointGT) other).p);
        return new MCLPointGT(result, curve(), group());
    }

    @Override
    protected final MCLPointGT subCore(Point other) {
        if (!(other instanceof MCLPointGT)) throw new IllegalArgumentException("不支持的点类型");
        GT result = new GT();
        Mcl.inv(result, ((MCLPointGT) other).p);
        Mcl.mul(result, p, result);
        return new MCLPointGT(result, curve(), group());
    }

    @Override
    protected final MCLPointGT mulCore(BigInteger scalar) {
        GT result = new GT();
        Mcl.pow(result, p, new Fr(scalar.toString()));
        return new MCLPointGT(result, curve(), group());
    }

    @Override
    protected final MCLPointGT negCore() {
        GT result = new GT();
        Mcl.inv(result, p);
        return new MCLPointGT(result, curve(), group());
    }

    // @Override
    // public final MCLPointGT copy() {
    //     return new MCLPointGT(p.(), curve(), group());
    // }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }
}
