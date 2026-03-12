package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

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
    protected final MCLPointZp mulCore(AdditivePoint scalar) {
        Fr result = new Fr();
        Mcl.mul(result, p, new Fr(scalar.toString()));
        return new MCLPointZp(result, curve(), group());
    }

    @Override
    public final MCLPointZp invZn() {
        Fr result = new Fr();
        Mcl.inv(result, p);
        return new MCLPointZp(result, curve(), group());
    }

    @Override
    protected final MCLPointZp negCore() {
        Fr result = new Fr();
        Mcl.neg(result, p);
        return new MCLPointZp(result, curve(), group());
    }

     @Override
     public final MCLPointZp copy() {
         return new MCLPointZp(new Fr(p), curve(), group());
     }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }

    @Override
    public final BigInteger toBigInteger() {
        return new BigInteger(p.toString());
    }

    @Override
    public final String toString() {
        return p.toString();
    }

    @Override
    public final boolean isEqual(Point other) {
        if(!(other instanceof MCLPointZp)) return false;
        return p.equals(((MCLPointZp) other).p);
    }
}
