package Commitment.DL;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Relation extends Commitment.Components.Relation {
    public Scalar x;
    public MultivePoint g, y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
