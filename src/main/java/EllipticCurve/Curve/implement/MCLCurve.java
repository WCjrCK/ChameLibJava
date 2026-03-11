package EllipticCurve.Curve.implement;

import java.util.Map;

import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import com.herumi.mcl.Fr;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Curve.GroupRepresentationProfile;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.implement.MCLPoint.*;

public class MCLCurve extends Curve {
    boolean swap_G1G2;
    public MCLCurve(CurveName curveName, GroupRepresentationProfile profile, Map<String, Object> params) {
        super(curveName, profile, params);
        if (!curveName.checkLib(CurveImplementLib.MCL)) throw new IllegalArgumentException("曲线 " + curveName + " 不属于 MCL 库");
        if (!params.containsKey("swap_G1G2")) this.swap_G1G2 = false;
        else this.swap_G1G2 = (Boolean) params.get("swap_G1G2");
        switch (curveName) {
            case BN254:
                Mcl.SystemInit(Mcl.BN254);
                break;

            case BLS12_381:
                Mcl.SystemInit(Mcl.BLS12_381);
                break;

            case SECP256K1:
                Mcl.SystemInit(Mcl.SECP256K1);
                break;

            default: throw new IllegalArgumentException("MCL 库不支持曲线：" + curveName);
        }
    }

    @Override
    protected Point newPoint(CurveGroup group) {
        switch (group) {
            case Zp: return new MCLPointZp(new Fr(), curveName(), group);
            case G1: 
                if (swap_G1G2) return new MCLPointG2(new G2(), curveName(), group);
                else return new MCLPointG1(new G1(), curveName(), group);
            case G2: 
                if (swap_G1G2) return new MCLPointG1(new G1(), curveName(), group);
                else return new MCLPointG2(new G2(), curveName(), group);
            case GT: return new MCLPointGT(new GT(), curveName(), group);
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
}
