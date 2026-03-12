package scheme.IBCH.implement.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class SecretKey extends scheme.Components.SecretKey {
    protected AdditivePoint S_ID; // G_1

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) S_ID);
        return res.toString();
    }
}
