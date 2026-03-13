package ABE.Components;

import ABE.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;

public abstract class PublicParam {
    public Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config.curveConfig);
    }

    public abstract String toString();

    public abstract String TheoSize();
}
