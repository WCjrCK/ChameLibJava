package Commitment.NIZK_DH_PAIR;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Witness extends Commitment.Components.Witness {
    Scalar x;
    MultivePoint u, g, v, h;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
