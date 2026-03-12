package scheme.IBCH.XSL_2021;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class SecretKey extends scheme.Components.SecretKey {
    protected MultivePoint tk_1, tk_2;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) tk_1);
        res.count((Point) tk_2);
        return res.toString();
    }
}
