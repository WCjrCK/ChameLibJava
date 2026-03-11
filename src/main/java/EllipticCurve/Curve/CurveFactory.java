package EllipticCurve.Curve;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import EllipticCurve.Point.PointRepresentation;
import EllipticCurve.Curve.implement.CurveImplementLib;
import EllipticCurve.Curve.implement.PBCCurve;
import EllipticCurve.Curve.implement.MCLCurve;

public final class CurveFactory {
    private CurveFactory() {}

    public static Curve create(CurveName curveName, GroupRepresentationProfile profile, Map<String, Object> params) {
        Objects.requireNonNull(curveName, "曲线名称不能为空");
        Objects.requireNonNull(profile, "群表示配置不能为空");
        if (curveName.checkLib(CurveImplementLib.PBC)) return new PBCCurve(curveName, profile, params);
        if (curveName.checkLib(CurveImplementLib.MCL)) return new MCLCurve(curveName, profile, params);
        throw new IllegalArgumentException("不支持的曲线类型: " + curveName);
    }

    public static Curve create(CurveName curveName) {
        return create(curveName, GroupRepresentationProfile.uniform(PointRepresentation.ADDITIVE), Collections.emptyMap());
    }

    public static Curve create(String curveName) {
        return create(CurveName.from(curveName));
    }

    public static Curve create(CurveName curveName, GroupRepresentationProfile profile) {
        return create(curveName, profile, Collections.emptyMap());
    }

    public static Curve create(String curveName, GroupRepresentationProfile profile) {
        return create(CurveName.from(curveName), profile, Collections.emptyMap());
    }

    public static Curve create(CurveName curveName, int representationMask) {
        return create(curveName, GroupRepresentationProfile.fromMask(representationMask), Collections.emptyMap());
    }

    public static Curve create(String curveName, int representationMask) {
        return create(CurveName.from(curveName), GroupRepresentationProfile.fromMask(representationMask));
    }

    public static Curve create(
            CurveName curveName,
            PointRepresentation g1,
            PointRepresentation g2,
            PointRepresentation gt
    ) {
        return create(curveName, GroupRepresentationProfile.of(g1, g2, gt), Collections.emptyMap());
    }

    public static Curve createUniform(CurveName curveName, PointRepresentation representation) {
        return create(curveName, GroupRepresentationProfile.uniform(representation), Collections.emptyMap());
    }

    public static List<GroupRepresentationProfile> allProfiles() {
        return GroupRepresentationProfile.all();
    }
}
