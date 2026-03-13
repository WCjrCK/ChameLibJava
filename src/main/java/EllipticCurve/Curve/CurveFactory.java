package EllipticCurve.Curve;

import EllipticCurve.Curve.implement.MCLCurve;
import EllipticCurve.Curve.implement.PBCCurve;

import static EllipticCurve.Curve.implement.CurveImplementLib.MCL;
import static EllipticCurve.Curve.implement.CurveImplementLib.PBC;

public final class CurveFactory {
    private CurveFactory() {}

    public static Curve create(Config config) {
        if (config.curveName.checkLib(PBC)) return new PBCCurve(config);
        if (config.curveName.checkLib(MCL)) return new MCLCurve(config);
        throw new IllegalArgumentException("不支持的曲线类型: " + config.curveName);
    }
}
