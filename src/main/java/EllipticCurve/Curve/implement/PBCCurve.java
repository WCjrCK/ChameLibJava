package EllipticCurve.Curve.implement;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Curve.GroupRepresentationProfile;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.implement.PBCPoint;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Map;

@SuppressWarnings("rawtypes")
public class PBCCurve extends Curve {
    Pairing pairing;
    boolean swap_G1G2;
    public Field Zp, G1, G2, GT;
    public PBCCurve(CurveName curveName, GroupRepresentationProfile profile, Map<String, Object> params) {
        super(curveName, profile, params);
        if (!curveName.checkLib(CurveImplementLib.PBC)) throw new IllegalArgumentException("曲线 " + curveName + " 不属于 PBC 库");
        final String base_path = "./jpbc/params/";
        String param_path;
        if(curveName == CurveName.PBC_CUSTOM) {
            if(!params.containsKey("param_file_path")) throw new IllegalArgumentException("自定义 PBC 曲线必须提供参数文件路径（param_file_path）");
            param_path = params.get("param_file_path").toString();
        }else param_path = base_path + curveName.name().toLowerCase() + ".properties";
        try {
            pairing = PairingFactory.getPairing(param_path);
        } catch (Exception e) {
            throw new IllegalArgumentException("曲线参数加载失败: " + e.getMessage() + " , 参数路径: " + param_path, e);
        }
        if (!params.containsKey("swap_G1G2")) this.swap_G1G2 = false;
        else this.swap_G1G2 = (Boolean) params.get("swap_G1G2");
        Zp = pairing.getZr();
        G1 = swap_G1G2 ? pairing.getG2() : pairing.getG1();
        G2 = swap_G1G2 ? pairing.getG1() : pairing.getG2();
        GT = pairing.getGT();
    }

    @Override
    protected PBCPoint newPoint(CurveGroup group) {
        switch (group) {
            case Zp: return new PBCPoint(Zp.newRandomElement().getImmutable(), curveName(), group);
            case G1: return new PBCPoint(G1.newRandomElement().getImmutable(), curveName(), swap_G1G2 ? CurveGroup.G2 : CurveGroup.G1);
            case G2: return new PBCPoint(G2.newRandomElement().getImmutable(), curveName(), swap_G1G2 ? CurveGroup.G1 : CurveGroup.G2);
            case GT: return new PBCPoint(GT.newRandomElement().getImmutable(), curveName(), group);
            default: throw new IllegalArgumentException("尚不支持当前曲线: " + curveName());
        }
    }

    @Override
    public PBCPoint Pairing(Point p1, Point p2) {
        if (p1.curve() != curveName()) throw new IllegalArgumentException("点 " + p1.curve() + " 不属于当前曲线: " + curveName());
        if (p2.curve() != curveName()) throw new IllegalArgumentException("点 " + p2.curve() + " 不属于当前曲线: " + curveName());
        if (pairing.isSymmetric() || ((PBCPoint) p1).p.getField() == G1 && ((PBCPoint) p2).p.getField() == G2) {
            PBCPoint pp1, pp2;
            if(this.swap_G1G2) {
                pp1 = (PBCPoint) p2;
                pp2 = (PBCPoint) p1;
            } else {
                pp1 = (PBCPoint) p1;
                pp2 = (PBCPoint) p2;
            }
            return new PBCPoint(pairing.pairing(pp1.p, pp2.p).getImmutable(), curveName(), CurveGroup.GT);
        } else throw new IllegalArgumentException("不支持的群类型: " + p1.group() + " , " + p2.group());
    }

    @Override
    public final PBCPoint HashToG1(byte[] hash) {
        return new PBCPoint(G1.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), swap_G1G2 ? CurveGroup.G2 : CurveGroup.G1);
    }

    @Override
    public final PBCPoint HashToG2(byte[] hash) {
        return new PBCPoint(G2.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), swap_G1G2 ? CurveGroup.G1 : CurveGroup.G2);
    }

    @Override
    public final PBCPoint HashToGT(byte[] hash) {
        return new PBCPoint(GT.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), CurveGroup.GT);
    }

    @Override
    public final PBCPoint HashToZp(byte[] hash) {
        return new PBCPoint(Zp.newElementFromHash(hash, 0, hash.length).getImmutable(), curveName(), CurveGroup.Zp);
    }
}
