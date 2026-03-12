package scheme.IBCH.XSL_2021;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class Randomness extends scheme.Components.Randomness {
    protected MultivePoint r_1, r_2;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) r_1);
        res.count((Point) r_2);
        return res.toString();
    }
}
