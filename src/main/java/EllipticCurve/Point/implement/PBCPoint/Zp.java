package EllipticCurve.Point.implement.PBCPoint;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Scalar;
import it.unisa.dia.gas.jpbc.Element;

public class Zp extends Scalar<Zp> {
    public Element p;

    public Zp(Element p, CurveName curve) {
        super(curve);
        this.p = p;
    }
    
    @Override
    protected final Zp addCore(Zp other) {
        return new Zp(p.add(other.p), curve());
    }
    
    @Override
    protected final Zp subCore(Zp other) {
        return new Zp(p.sub(other.p), curve());
    }

    @Override
    protected final Zp mulCore(Zp scalar) {
        return new Zp(p.mulZn(scalar.p), curve());
    }

    @Override
    protected final Zp divCore(Zp scalar) {
        return new Zp(p.mulZn(scalar.p.invert()), curve());
    }
    
    @Override
    protected final Zp negCore() {
        return new Zp(p.negate(), curve());
    }

    @Override
    public final Zp inv() {
        return new Zp(p.invert(), curve());
    }

     @Override
     public final Zp copy() {
         return new Zp(p.duplicate(), curve());
     }

    @Override
    public final String toString() {
        return p.toString();
    }

    @Override
    public final boolean isEqual(Zp other) {
        return p.isEqual(other.p);
    }

    @Override
    public boolean isOne() {
        return p.isOne();
    }

    @Override
    public boolean isZero() {
        return p.isZero();
    }
}
