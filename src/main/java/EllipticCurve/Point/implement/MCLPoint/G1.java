package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class G1 extends Point<G1, Zp> {
    public com.herumi.mcl.G1 p;

    public G1(com.herumi.mcl.G1 p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final G1 addCore(G1 other) {
        com.herumi.mcl.G1 result = new com.herumi.mcl.G1();
        Mcl.add(result, p, other.p);
        return new G1(result, curve(), group());
    }
    
    @Override
    protected final G1 subCore(G1 other) {
        com.herumi.mcl.G1 result = new com.herumi.mcl.G1();
        Mcl.sub(result, p, other.p);
        return new G1(result, curve(), group());
    }

    @Override
    protected final G1 mulCore(Zp scalar) {
        com.herumi.mcl.G1 result = new com.herumi.mcl.G1();
        Mcl.mul(result, p, scalar.p);
        return new G1(result, curve(), group());
    }

    @Override
    protected final G1 divCore(Zp scalar) {
        com.herumi.mcl.G1 result = new com.herumi.mcl.G1();
        Mcl.mul(result, p, scalar.inv().p);
        return new G1(result, curve(), group());
    }
    
    @Override
    protected final G1 negCore() {
        com.herumi.mcl.G1 result = new com.herumi.mcl.G1();
        Mcl.neg(result, p);
        return new G1(result, curve(), group());
    }

    @Override
    public final G1 copy() {
        return new G1(new com.herumi.mcl.G1(p), curve(), group());
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
    public final boolean isEqual(G1 other) {
        return p.equals(other.p);
    }
}
