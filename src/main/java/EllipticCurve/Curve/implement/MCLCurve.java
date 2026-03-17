package EllipticCurve.Curve.implement;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.implement.MCLPoint.G1;
import EllipticCurve.Point.implement.MCLPoint.G2;
import EllipticCurve.Point.implement.MCLPoint.GT;
import EllipticCurve.Point.implement.MCLPoint.Zp;
import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Random;

public class MCLCurve extends Curve<G1, G2, GT, Zp> {
    public MCLCurve(Config config) {
        super(config);
        System.loadLibrary("mcljava");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if (!config.curveName.checkLib(CurveImplementLib.MCL)) throw new IllegalArgumentException("曲线 " + config.curveName + " 不属于 MCL 库");
        switch (config.curveName) {
            case BN254:
                Mcl.SystemInit(Mcl.BN254);
                break;

            case BLS12_381:
                Mcl.SystemInit(Mcl.BLS12_381);
                break;

            case SECP256K1:
                Mcl.SystemInit(Mcl.SECP256K1);
                break;

            default: throw new IllegalArgumentException("尚不支持当前曲线：" + config.curveName);
        }
    }

    @Override
    protected G1 createG1() {
        byte[] m = new byte[128];
        Random random = new Random();
        random.nextBytes(m);
        return HashToG1Core(m);
    }

    @Override
    protected G2 createG2() {
        byte[] m = new byte[128];
        Random random = new Random();
        random.nextBytes(m);
        return HashToG2Core(m);
    }

    @Override
    protected GT createGT() {
        byte[] m = new byte[128];
        Random random = new Random();
        random.nextBytes(m);
        return HashToGTCore(m);
    }

    @Override
    protected Zp createZp() {
        byte[] m = new byte[128];
        Random random = new Random();
        random.nextBytes(m);
        return HashToZpCore(m);
    }

    @Override
    protected G1 getOneG1() {
        throw new RuntimeException("暂未实现MCL的G1群单位元获取");
    }

    @Override
    protected G2 getOneG2() {
        throw new RuntimeException("暂未实现MCL的G2群单位元获取");
    }

    @Override
    protected GT getOneGT() {
        GT res = createGT();
        return (GT) res.div(res);
    }

    @Override
    protected Zp getOneZp() {
        return new Zp(new Fr(1), curveName());
    }

    @Override
    protected G1 getZeroG1() {
        throw new RuntimeException("暂未实现MCL的G1群零元获取");
    }

    @Override
    protected G2 getZeroG2() {
        throw new RuntimeException("暂未实现MCL的G2群零元获取");
    }

    @Override
    protected GT getZeroGT() {
        throw new RuntimeException("暂未实现MCL的GT群零元获取");
    }

    @Override
    protected Zp getZeroZp() {
        return new Zp(new Fr(0), curveName());
    }

    @Override
    public final G2 PowNdonrCore(G2 p) {
        return p;
    }

    @Override
    public Zp createScalarFromString(String s) {
        return new Zp(new Fr(s), curveName());
    }

    @Override
    protected GT Pairing(G1 p1, G2 p2) {
        if (p1.curve() != curveName()) throw new IllegalArgumentException("点 " + p1.curve() + " 不属于当前曲线: " + curveName());
        if (p2.curve() != curveName()) throw new IllegalArgumentException("点 " + p2.curve() + " 不属于当前曲线: " + curveName());
        try {
            com.herumi.mcl.GT result = new com.herumi.mcl.GT();
            Mcl.pairing(result, p1.p, p2.p);
            return new GT(result, curveName(), CurveGroup.GT);
        } catch (Exception e) {
            throw new IllegalArgumentException("点类型错误: " + e.getMessage(), e);
        }
    }

    @Override
    protected G1 createG1FromBytes(byte[] data) {
        com.herumi.mcl.G1 res = new com.herumi.mcl.G1();
        res.deserialize(data);
        return new G1(res, curveName(), CurveGroup.G1);
    }

    @Override
    protected G2 createG2FromBytes(byte[] data) {
        com.herumi.mcl.G2 res = new com.herumi.mcl.G2();
        res.deserialize(data);
        return new G2(res, curveName(), CurveGroup.G2);
    }

    @Override
    protected GT createGTFromBytes(byte[] data) {
        com.herumi.mcl.GT res = new com.herumi.mcl.GT();
        res.deserialize(data);
        return new GT(res, curveName(), CurveGroup.GT);
    }

    @Override
    protected Zp createZpFromBytes(byte[] data) {
        Fr res = new Fr();
        res.deserialize(data);
        return new Zp(res, curveName());
    }

    @Override
    public final G1 HashToG1Core(byte[] hash) {
        com.herumi.mcl.G1 res = new com.herumi.mcl.G1();
        Mcl.hashAndMapToG1(res, hash);
        return new G1(res, curveName(), CurveGroup.G1);
    }

    @Override
    public final G2 HashToG2Core(byte[] hash) {
        com.herumi.mcl.G2 res = new com.herumi.mcl.G2();
        Mcl.hashAndMapToG2(res, hash);
        return new G2(res, curveName(), CurveGroup.G2);
    }

    @Override
    public final GT HashToGTCore(byte[] hash) {
        com.herumi.mcl.GT res = new com.herumi.mcl.GT();
        com.herumi.mcl.G1 tmp1 = new com.herumi.mcl.G1();
        com.herumi.mcl.G2 tmp2 = new com.herumi.mcl.G2();
        Mcl.hashAndMapToG1(tmp1, hash);
        Mcl.hashAndMapToG2(tmp2, hash);
        Mcl.pairing(res, tmp1, tmp2);
        return new GT(res, curveName(), CurveGroup.GT);
    }

    @Override
    public final Zp HashToZpCore(byte[] hash) {
        Fr res = new Fr();
        res.setHashOf(hash);
        return new Zp(res, curveName());
    }
}
