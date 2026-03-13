package EllipticCurve.Curve.implement;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.implement.MCLPoint.MCLPointG1;
import EllipticCurve.Point.implement.MCLPoint.MCLPointG2;
import EllipticCurve.Point.implement.MCLPoint.MCLPointGT;
import EllipticCurve.Point.implement.MCLPoint.MCLPointZp;
import com.herumi.mcl.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Random;

public class MCLCurve extends Curve {
    boolean swap_G1G2;
    public MCLCurve(Config config) {
        super(config);
        System.loadLibrary("mcljava");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if (!config.curveName.checkLib(CurveImplementLib.MCL)) throw new IllegalArgumentException("曲线 " + config.curveName + " 不属于 MCL 库");
        if (!config.params.containsKey("swap_G1G2")) this.swap_G1G2 = false;
        else this.swap_G1G2 = (Boolean) config.params.get("swap_G1G2");
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
    protected Point newPoint(CurveGroup group) {
        byte[] m = new byte[128];
        Random random = new Random();
        random.nextBytes(m);
        switch (group) {
            case Zp: return HashToZp(m);
            case G1: return HashToG1(m);
            case G2: return HashToG2(m);
            case GT: return HashToGT(m);
            default: throw new IllegalArgumentException("尚不支持当前曲线: " + curveName());
        }
    }

    @Override
    public MCLPointGT Pairing(Point p1, Point p2) {
        if (p1.curve() != curveName()) throw new IllegalArgumentException("点 " + p1.curve() + " 不属于当前曲线: " + curveName());
        if (p2.curve() != curveName()) throw new IllegalArgumentException("点 " + p2.curve() + " 不属于当前曲线: " + curveName());
        try {
            GT result = new GT();
            if (swap_G1G2) Mcl.pairing(result, ((MCLPointG1) p2).p, ((MCLPointG2) p1).p);
            else Mcl.pairing(result, ((MCLPointG1) p1).p, ((MCLPointG2) p2).p);
            return new MCLPointGT(result, curveName(), CurveGroup.GT);
        } catch (Exception e) {
            throw new IllegalArgumentException("点类型错误: " + e.getMessage(), e);
        }
    }

    @Override
    public final Point HashToG1(byte[] hash) {
        if (swap_G1G2) {
            G2 res = new G2();
            Mcl.hashAndMapToG2(res, hash);
            return new MCLPointG2(res, curveName(), CurveGroup.G2);
        } else {
            G1 res = new G1();
            Mcl.hashAndMapToG1(res, hash);
            return new MCLPointG1(res, curveName(), CurveGroup.G1);
        }
    }

    @Override
    public final Point HashToG2(byte[] hash) {
        if (swap_G1G2) {
            G1 res = new G1();
            Mcl.hashAndMapToG1(res, hash);
            return new MCLPointG1(res, curveName(), CurveGroup.G1);
        } else {
            G2 res = new G2();
            Mcl.hashAndMapToG2(res, hash);
            return new MCLPointG2(res, curveName(), CurveGroup.G2);
        }
    }

    @Override
    public final MCLPointGT HashToGT(byte[] hash) {
        GT res = new GT();
        G1 tmp1 = new G1();
        G2 tmp2 = new G2();
        Mcl.hashAndMapToG1(tmp1, hash);
        Mcl.hashAndMapToG2(tmp2, hash);
        Mcl.pairing(res, tmp1, tmp2);
        return new MCLPointGT(res, curveName(), CurveGroup.GT);
    }

    @Override
    public final MCLPointZp HashToZp(byte[] hash) {
        Fr res = new Fr();
        res.setHashOf(hash);
        return new MCLPointZp(res, curveName(), CurveGroup.Zp);
    }
}
