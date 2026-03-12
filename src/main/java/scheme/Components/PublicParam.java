package scheme.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import EllipticCurve.Curve.CurveName;

import java.util.Map;

public abstract class PublicParam {
    public Curve curve;

    protected PublicParam(CurveName curveName, Map<String, Object> params) {
        curve = CurveFactory.create(curveName, (Map<String, Object>) params.get("curve_param"));
    }

    public abstract String toString();

    public abstract String TheoSize();
}
