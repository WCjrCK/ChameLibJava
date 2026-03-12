package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class SecretKey extends scheme.Components.SecretKey {
    protected AdditivePoint td_1;
    protected MultivePoint td_2;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) td_1);
        res.count((Point) td_2);
        return res.toString();
    }
}
