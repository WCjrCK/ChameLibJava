package EllipticCurve.Point.implement.PBCPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;
import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

public class Group extends Point<Group, Zp> {
    public Element p;

    public Group(Element p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }
    
    @Override
    protected final Group addCore(Group other) {
        return new Group(p.add(other.p), curve(), group());
    }
    
    @Override
    protected final Group subCore(Group other) {
        return new Group(p.sub(other.p), curve(), group());
    }

    @Override
    protected final Group mulCore(Zp scalar) {
        return new Group(p.mulZn(scalar.p), curve(), group());
    }

    @Override
    protected final Group divCore(Zp scalar) {
        return new Group(p.mulZn(scalar.p.invert()), curve(), group());
    }
    
    @Override
    protected final Group negCore() {
        return new Group(p.negate(), curve(), group());
    }

    @Override
     public final Group copy() {
         return new Group(p.duplicate(), curve(), group());
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
    public final boolean isEqual(Group other) {
        return p.isEqual(other.p);
    }
}
