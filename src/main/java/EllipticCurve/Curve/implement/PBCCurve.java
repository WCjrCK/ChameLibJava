package EllipticCurve.Curve.implement;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.implement.PBCPoint.Group;
import EllipticCurve.Point.implement.PBCPoint.Zp;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

@SuppressWarnings("rawtypes")
public class PBCCurve extends Curve<Group, Group, Group, Zp> {
    final Pairing pairing;
    public final Field Zp, G1, G2, GT;
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
    protected Group Pairing(Group p1, Group p2) {
        if (p1.curve() != curveName()) throw new IllegalArgumentException("点 " + p1.curve() + " 不属于当前曲线: " + curveName());
        if (p2.curve() != curveName()) throw new IllegalArgumentException("点 " + p2.curve() + " 不属于当前曲线: " + curveName());
        if (pairing.isSymmetric() || ((Group) p1).p.getField() == G1 && ((Group) p2).p.getField() == G2) {
            return new Group(pairing.pairing(p1.p, p2.p).getImmutable(), curveName(), CurveGroup.GT);
        } else throw new IllegalArgumentException("不支持的群类型: " + p1.group() + " , " + p2.group());
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
}
