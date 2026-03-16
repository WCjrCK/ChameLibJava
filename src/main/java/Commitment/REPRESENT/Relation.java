package Commitment.REPRESENT;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Relation extends Commitment.Components.Relation {
    Scalar x_1, x_2;
    MultivePoint g_1, g_2, y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
