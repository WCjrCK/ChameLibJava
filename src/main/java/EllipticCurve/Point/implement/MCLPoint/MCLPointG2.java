package EllipticCurve.Point.implement.MCLPoint;

import java.math.BigInteger;

import com.herumi.mcl.Mcl;
import com.herumi.mcl.G2;
import com.herumi.mcl.Fr;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;

public class MCLPointG2 extends Point {
    public G2 p;

    public MCLPointG2(G2 p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final MCLPointG2 addCore(Point other) {
        if (!(other instanceof MCLPointG2)) throw new IllegalArgumentException("不支持的点类型");
        G2 result = new G2();
        Mcl.add(result, p, ((MCLPointG2) other).p);
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    protected final MCLPointG2 subCore(Point other) {
        if (!(other instanceof MCLPointG2)) throw new IllegalArgumentException("不支持的点类型");
        G2 result = new G2();
        Mcl.sub(result, p, ((MCLPointG2) other).p);
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    protected final MCLPointG2 mulCore(BigInteger scalar) {
        G2 result = new G2();
        Mcl.mul(result, p, new Fr(scalar.toString()));
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    protected final MCLPointG2 negCore() {
        G2 result = new G2();
        Mcl.neg(result, p);
        return new MCLPointG2(result, curve(), group());
    }

    // @Override
    // public final MCLPointG2 copy() {
    //     return new MCLPointG2(p.(), curve(), group());
    // }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }
}
