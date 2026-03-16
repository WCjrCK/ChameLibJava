package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class G2 extends Point<G2, Zp> {
    public com.herumi.mcl.G2 p;

    public G2(com.herumi.mcl.G2 p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final G2 addCore(G2 other) {
        com.herumi.mcl.G2 result = new com.herumi.mcl.G2();
        Mcl.add(result, p, other.p);
        return new G2(result, curve(), group());
    }

    @Override
    protected final G2 subCore(G2 other) {
        com.herumi.mcl.G2 result = new com.herumi.mcl.G2();
        Mcl.sub(result, p, other.p);
        return new G2(result, curve(), group());
    }

    @Override
    protected final G2 mulCore(Zp scalar) {
        com.herumi.mcl.G2 result = new com.herumi.mcl.G2();
        Mcl.mul(result, p, scalar.p);
        return new G2(result, curve(), group());
    }

    @Override
    protected final G2 divCore(Zp scalar) {
        com.herumi.mcl.G2 result = new com.herumi.mcl.G2();
        Mcl.mul(result, p, scalar.inv().p);
        return new G2(result, curve(), group());
    }

    @Override
    protected final G2 negCore() {
        com.herumi.mcl.G2 result = new com.herumi.mcl.G2();
        Mcl.neg(result, p);
        return new G2(result, curve(), group());
    }

    @Override
    public final G2 copy() {
        return new G2(new com.herumi.mcl.G2(p), curve(), group());
    }

    @Override
    public final byte[] toBytes() {
        return p.serialize();
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
    public final boolean isEqual(G2 other) {
        return p.equals(other.p);
    }
}
