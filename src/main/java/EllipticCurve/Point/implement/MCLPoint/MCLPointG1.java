package EllipticCurve.Point.implement.MCLPoint;

import java.math.BigInteger;

import com.herumi.mcl.Mcl;
import com.herumi.mcl.G1;
import com.herumi.mcl.Fr;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;

public class MCLPointG1 extends Point {
    public G1 p;

    public MCLPointG1(G1 p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }
    
    @Override
    protected final MCLPointG1 addCore(Point other) {
        if (!(other instanceof MCLPointG1)) throw new IllegalArgumentException("不支持的点类型");
        G1 result = new G1();
        Mcl.add(result, p, ((MCLPointG1) other).p);
        return new MCLPointG1(result, curve(), group());
    }
    
    @Override
    protected final MCLPointG1 subCore(Point other) {
        if (!(other instanceof MCLPointG1)) throw new IllegalArgumentException("不支持的点类型");
        G1 result = new G1();
        Mcl.sub(result, p, ((MCLPointG1) other).p);
        return new MCLPointG1(result, curve(), group());
    }
    
    @Override
    protected final MCLPointG1 mulCore(BigInteger scalar) {
        G1 result = new G1();
        Mcl.mul(result, p, new Fr(scalar.toString()));
        return new MCLPointG1(result, curve(), group());
    }
    
    @Override
    protected final MCLPointG1 negCore() {
        G1 result = new G1();
        Mcl.neg(result, p);
        return new MCLPointG1(result, curve(), group());
    }

    // @Override
    // public final MCLPointG1 copy() {
    //     return new MCLPointG1(p.(), curve(), group());
    // }

    @Override
    public final byte[] toBytes() {
        throw new UnsupportedOperationException("MCLPoint 不支持序列化");
    }
}
