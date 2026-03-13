package EllipticCurve.Curve;

import EllipticCurve.Point.PointRepresentation;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Config {
    public CurveName curveName;
    public PointRepresentation G1r, G2r, GTr;
    public Map<String, Object> params;

    public Config(CurveName curveName, PointRepresentation G1r, PointRepresentation G2r, PointRepresentation GTr, Map<String, Object> params) {
        this.curveName = Objects.requireNonNull(curveName, "曲线名称不能为空");
        this.G1r = Objects.requireNonNull(G1r, "G1表示不能为空");
        this.G2r = Objects.requireNonNull(G2r, "G2表示不能为空");
        this.GTr = Objects.requireNonNull(GTr, "GT表示不能为空");
        this.params = params;
    }

    public Config(CurveName curveName, PointRepresentation G1r, PointRepresentation G2r, PointRepresentation GTr) {
        this(curveName, G1r, G2r, GTr, new HashMap<>());
    }

    public Config(CurveName curveName) {
        this(curveName, PointRepresentation.ADDITIVE, PointRepresentation.ADDITIVE, PointRepresentation.MULTIVE);
    }

    public Config(CurveName curveName, PointRepresentation G) {
        this(curveName, G, G, G);
    }

    public Config(CurveName curveName, Map<String, Object> params) {
        this(curveName, PointRepresentation.ADDITIVE, PointRepresentation.ADDITIVE, PointRepresentation.MULTIVE, params);
    }
}
