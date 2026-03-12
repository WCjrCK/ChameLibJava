package SE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.PointRepresentation;

import java.util.Map;

public abstract class PublicParam {
    public Curve curve;

    protected PublicParam(CurveName curveName, Map<String, Object> params) {
        curve = CurveFactory.create(curveName, (Map<String, Object>) params.get("curve_param"));
    }

    protected PublicParam(CurveName curveName, PointRepresentation PR, Map<String, Object> params) {
        curve = CurveFactory.create(curveName, PR, (Map<String, Object>) params.get("curve_param"));
    }

    public abstract String toString();

    public abstract String TheoSize();
}
