package EllipticCurve.Curve;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import EllipticCurve.Point.PointRepresentation;
import EllipticCurve.Curve.implement.PBCCurve;
import EllipticCurve.Curve.implement.MCLCurve;

import static EllipticCurve.Curve.implement.CurveImplementLib.*;

public final class CurveFactory {
    private CurveFactory() {}

    public static Curve create(CurveName curveName, PointRepresentation G1r, PointRepresentation G2r, PointRepresentation GTr, Map<String, Object> params) {
        Objects.requireNonNull(curveName, "曲线名称不能为空");
        Objects.requireNonNull(G1r, "G1表示不能为空");
        Objects.requireNonNull(G2r, "G2表示不能为空");
        Objects.requireNonNull(GTr, "GT表示不能为空");
        GroupRepresentationProfile profile = GroupRepresentationProfile.of(G1r, G2r, GTr);
        if (curveName.checkLib(PBC)) return new PBCCurve(curveName, profile, params);
        if (curveName.checkLib(MCL)) return new MCLCurve(curveName, profile, params);
        throw new IllegalArgumentException("不支持的曲线类型: " + curveName);
    }

    public static Curve create(CurveName curveName, Map<String, Object> params) {
        return create(curveName, PointRepresentation.ADDITIVE, PointRepresentation.ADDITIVE, PointRepresentation.MULTIVE, params);
    }

    public static Curve create(CurveName curveName, PointRepresentation r) {
        return create(curveName, r, r, r, Collections.emptyMap());
    }
}
