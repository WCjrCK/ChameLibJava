package EllipticCurve.Point.implement;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

public class PBCPoint extends Point {
    public Element p;

    public PBCPoint(Element p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }
    
    @Override
    protected final PBCPoint addCore(Point other) {
        if (other instanceof PBCPoint) return new PBCPoint(p.add(((PBCPoint) other).p), curve(), group());
        else throw new IllegalArgumentException("不支持的点类型");
    }
    
    @Override
    protected final PBCPoint subCore(Point other) {
        if (other instanceof PBCPoint) return new PBCPoint(p.sub(((PBCPoint) other).p), curve(), group());
        else throw new IllegalArgumentException("不支持的点类型");
    }
    
    @Override
    protected final PBCPoint mulCore(AdditivePoint scalar) {
        return new PBCPoint(p.mulZn(((PBCPoint) scalar).p), curve(), group());
    }
    
    @Override
    protected final PBCPoint negCore() {
        return new PBCPoint(p.negate(), curve(), group());
    }

    @Override
    public final PBCPoint invZn() {
        return new PBCPoint(p.invert(), curve(), group());
    }

     @Override
     public final PBCPoint copy() {
         return new PBCPoint(p.duplicate(), curve(), group());
     }

    @Override
    public final byte[] toBytes() {
        return p.toBytes();
    }

    @Override
    public final BigInteger toBigInteger() {
        return p.toBigInteger();
    }

    @Override
    public final String toString() {
        return p.toString();
    }

    @Override
    public final boolean isEqual(Point other) {
        if(!(other instanceof PBCPoint)) return false;
        return p.isEqual(((PBCPoint) other).p);
    }
}
