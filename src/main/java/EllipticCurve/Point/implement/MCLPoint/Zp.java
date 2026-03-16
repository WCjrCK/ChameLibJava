package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Scalar;
import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;

public class Zp extends Scalar<Zp> {
    public Fr p;

    public Zp(Fr p, CurveName curve) {
        super(curve);
        this.p = p;
    }

    @Override
    protected final Zp addCore(Zp other) {
        Fr result = new Fr();
        Mcl.add(result, p, other.p);
        return new Zp(result, curve());
    }

    @Override
    protected final Zp subCore(Zp other) {
        Fr result = new Fr();
        Mcl.sub(result, p, other.p);
        return new Zp(result, curve());
    }

    @Override
    protected final Zp mulCore(Zp scalar) {
        Fr result = new Fr();
        Mcl.mul(result, p, scalar.p);
        return new Zp(result, curve());
    }

    @Override
    protected final Zp divCore(Zp scalar) {
        Fr result = new Fr();
        Mcl.div(result, p, scalar.p);
        return new Zp(result, curve());
    }

    @Override
    public final Zp inv() {
        Fr result = new Fr();
        Mcl.inv(result, p);
        return new Zp(result, curve());
    }

    @Override
    protected final Zp negCore() {
        Fr result = new Fr();
        Mcl.neg(result, p);
        return new Zp(result, curve());
    }

     @Override
     public final Zp copy() {
         return new Zp(new Fr(p), curve());
     }

    @Override
    public final String toString() {
        return p.toString();
    }

    @Override
    public final boolean isEqual(Zp other) {
        return p.equals(other.p);
    }

    @Override
    public byte[] toBytes() {
        return p.serialize();
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
