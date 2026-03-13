package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

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
    protected final MCLPointG2 mulCore(AdditivePoint scalar) {
        G2 result = new G2();
        Mcl.mul(result, p, ((MCLPointZp) scalar).p);
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    protected final MCLPointG2 negCore() {
        G2 result = new G2();
        Mcl.neg(result, p);
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    public final MCLPointG2 invZn() {
        G2 result = new G2();
        Mcl.neg(result, p);
        return new MCLPointG2(result, curve(), group());
    }

    @Override
    public final MCLPointG2 copy() {
        return new MCLPointG2(new G2(p), curve(), group());
    }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }

    @Override
    public final BigInteger toBigInteger() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }

    @Override
    public final String toString() {
        return p.toString();
    }

    @Override
    public final boolean isEqual(Point other) {
        if(!(other instanceof MCLPointG2)) return false;
        return p.equals(((MCLPointG2) other).p);
    }
}
