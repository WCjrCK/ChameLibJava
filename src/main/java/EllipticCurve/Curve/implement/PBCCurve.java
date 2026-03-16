package EllipticCurve.Curve.implement;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.implement.PBCPoint.Group;
import EllipticCurve.Point.implement.PBCPoint.Zp;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;

@SuppressWarnings("rawtypes")
public class PBCCurve extends Curve<Group, Group, Group, Zp> {
    final Pairing pairing;
    public final Field Zp, G1, G2, GT;
    public final BigInteger G2_ndonr;

    private BigInteger pbc_mpz_trace_n(BigInteger q, BigInteger trace, int n) {
        int i;
        BigInteger c2 = BigInteger.TWO;
        BigInteger c1 = trace;
        BigInteger c0, t0;
        for (i=2; i<=n; i++) {
            c0 = trace.multiply(c1);
            t0 = q.multiply(c2);
            c0 = c0.subtract(t0);
            c2 = c1;
            c1 = c0;
        }
        return c1;
    }

    private BigInteger pbc_mpz_curve_order_extn(BigInteger q, BigInteger t, int k) {
        return q.pow(k).add(BigInteger.ONE).subtract(pbc_mpz_trace_n(q, t, k));
    }

    public PBCCurve(Config config) {
        super(config);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if (!config.curveName.checkLib(CurveImplementLib.PBC)) throw new IllegalArgumentException("曲线 " + config.curveName + " 不属于 PBC 库");
        final String base_path = "./jpbc/params/";
        String param_path;
        if(config.curveName == CurveName.PBC_CUSTOM) {
            if(!config.params.containsKey("param_file_path")) throw new IllegalArgumentException("自定义 PBC 曲线必须提供参数文件路径（param_file_path）");
            param_path = config.params.get("param_file_path").toString();
        } else param_path = base_path + config.curveName.name().toLowerCase() + ".properties";
        try {
            pairing = PairingFactory.getPairing(param_path);
        } catch (Exception e) {
            throw new IllegalArgumentException("曲线参数加载失败: " + e.getMessage() + " , 参数路径: " + param_path, e);
        }
        Zp = pairing.getZr();
        G1 = pairing.getG1();
        G2 = pairing.getG2();
        GT = pairing.getGT();

        PairingParameters param = PairingFactory.getPairingParameters(param_path);
        switch (param.getString("type")) {
            case "d":
                this.G2_ndonr = pbc_mpz_curve_order_extn(
                            param.getBigInteger("q"),
                            param.getBigInteger("q").subtract(param.getBigInteger("n")).add(BigInteger.ONE).negate(),
                            (int) (param.getBigInteger("k").divide(BigInteger.TWO)).longValueExact()
                    ).divide(param.getBigInteger("r"));
                break;
            case "f":
                this.G2_ndonr = pbc_mpz_curve_order_extn(
                            param.getBigInteger("q"),
                            param.getBigInteger("q").subtract(param.getBigInteger("r")).add(BigInteger.ONE),
                            12
                    ).divide(param.getBigInteger("r")).divide(param.getBigInteger("r"));
                break;
            case "g":
                this.G2_ndonr = pbc_mpz_curve_order_extn(
                            param.getBigInteger("q"),
                            param.getBigInteger("q").subtract(param.getBigInteger("n")).add(BigInteger.ONE).negate(),
                            5
                    ).divide(param.getBigInteger("r"));
                break;
            default:
                this.G2_ndonr = BigInteger.ONE;
                break;
        }
    }

    @Override
    protected Group createG1() {
        return new Group(G1.newRandomElement().getImmutable(), curveName(), CurveGroup.G1);
    }

    @Override
    protected Group createG2() {
        return new Group(G2.newRandomElement().getImmutable(), curveName(), CurveGroup.G2);
    }

    @Override
    protected Group createGT() {
        return new Group(GT.newRandomElement().getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    protected Zp createZp() {
        return new Zp(Zp.newRandomElement().getImmutable(), curveName());
    }

    @Override
    protected Group getOneG1() {
        return new Group(G1.newOneElement().getImmutable(), curveName(), CurveGroup.G1);
    }

    @Override
    protected Group getOneG2() {
        return new Group(G2.newOneElement().getImmutable(), curveName(), CurveGroup.G2);
    }

    @Override
    protected Group getOneGT() {
        return new Group(GT.newOneElement().getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    protected Zp getOneZp() {
        return new Zp(Zp.newOneElement().getImmutable(), curveName());
    }

    @Override
    protected Group getZeroG1() {
        return new Group(G1.newZeroElement().getImmutable(), curveName(), CurveGroup.G1);
    }

    @Override
    protected Group getZeroG2() {
        return new Group(G2.newZeroElement().getImmutable(), curveName(), CurveGroup.G2);
    }

    @Override
    protected Group getZeroGT() {
        return new Group(GT.newZeroElement().getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    protected Zp getZeroZp() {
        return new Zp(Zp.newZeroElement().getImmutable(), curveName());
    }

    @Override
    protected Group Pairing(Group p1, Group p2) {
        if (p1.curve() != curveName()) throw new IllegalArgumentException("点 " + p1.curve() + " 不属于当前曲线: " + curveName());
        if (p2.curve() != curveName()) throw new IllegalArgumentException("点 " + p2.curve() + " 不属于当前曲线: " + curveName());
        if (pairing.isSymmetric() || ((Group) p1).p.getField() == G1 && ((Group) p2).p.getField() == G2) {
            return new Group(pairing.pairing(p1.p, p2.p).getImmutable(), curveName(), CurveGroup.GT);
        } else throw new IllegalArgumentException("不支持的群类型: " + p1.group() + " , " + p2.group());
    }

    @Override
    protected Group createG1FromBytes(byte[] data) {
        return new Group(G1.newElementFromBytes(data).getImmutable(), curveName(), CurveGroup.G1);
    }

    @Override
    protected Group createG2FromBytes(byte[] data) {
        return new Group(G2.newElementFromBytes(data).getImmutable(), curveName(), CurveGroup.G2);
    }

    @Override
    protected Group createGTFromBytes(byte[] data) {
        return new Group(GT.newElementFromBytes(data).getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    public final Group HashToG1Core(byte[] hash) {
        return new Group(G1.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), CurveGroup.G1);
    }

    @Override
    public final Group HashToG2Core(byte[] hash) {
        return new Group(G2.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), CurveGroup.G2);
    }

    @Override
    public final Group HashToGTCore(byte[] hash) {
        return new Group(GT.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    public final Zp HashToZpCore(byte[] hash) {
        return new Zp(Zp.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName());
    }

    @Override
    public final Group PowNdonrCore(Group p) {
        if (p.group() == CurveGroup.G2) return new Group(p.p.pow(G2_ndonr).getImmutable(), curveName(), CurveGroup.G2);
        return p;
    }

    @Override
    public Zp createScalarFromString(String s) {
        return new Zp(Zp.newElement(new BigInteger(s)).getImmutable(), curveName());
    }
}
