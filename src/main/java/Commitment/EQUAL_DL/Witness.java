package Commitment.EQUAL_DL;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Witness extends Commitment.Components.Witness {
    Scalar x;
    MultivePoint g_1, g_2, y_1, y_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
