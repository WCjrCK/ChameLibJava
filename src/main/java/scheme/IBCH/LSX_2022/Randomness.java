package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class Randomness extends scheme.Components.Randomness {
    protected AdditivePoint r_1;
    protected MultivePoint r_2;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) r_1);
        res.count((Point) r_2);
        return res.toString();
    }
}
