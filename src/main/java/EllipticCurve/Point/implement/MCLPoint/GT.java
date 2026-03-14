package EllipticCurve.Point.implement.MCLPoint;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.Point;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class GT extends Point<GT, Zp> {
    public com.herumi.mcl.GT p;

    public GT(com.herumi.mcl.GT p, CurveName curve, CurveGroup group) {
        super(curve, group);
        this.p = p;
    }

    @Override
    protected final GT addCore(GT other) {
        com.herumi.mcl.GT result = new com.herumi.mcl.GT();
        Mcl.mul(result, p, other.p);
        return new GT(result, curve(), group());
    }

    @Override
    protected final GT subCore(GT other) {
        com.herumi.mcl.GT result = new com.herumi.mcl.GT();
        Mcl.inv(result, other.p);
        Mcl.mul(result, p, result);
        return new GT(result, curve(), group());
    }

    @Override
    protected final GT mulCore(Zp scalar) {
        com.herumi.mcl.GT result = new com.herumi.mcl.GT();
        Mcl.pow(result, p, scalar.p);
        return new GT(result, curve(), group());
    }

    @Override
    protected final GT divCore(Zp scalar) {
        com.herumi.mcl.GT result = new com.herumi.mcl.GT();
        Mcl.pow(result, p, scalar.inv().p);
        return new GT(result, curve(), group());
    }

    @Override
    protected final GT negCore() {
        com.herumi.mcl.GT result = new com.herumi.mcl.GT();
        Mcl.inv(result, p);
        return new GT(result, curve(), group());
    }

    @Override
    public final GT copy() {
        return new GT(new com.herumi.mcl.GT(p), curve(), group());
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
    public final boolean isEqual(GT other) {
        return p.equals(other.p);
    }
}
