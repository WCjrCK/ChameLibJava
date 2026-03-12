package scheme.IBCH.XSL_2021;

import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected MultivePoint g_2_alpha;

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) g_2_alpha);
        return res.toString();
    }
}
