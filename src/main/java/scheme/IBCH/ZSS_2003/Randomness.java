package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class Randomness extends scheme.Components.Randomness {
    protected AdditivePoint R; // G_1

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) R);
        return res.toString();
    }
}
