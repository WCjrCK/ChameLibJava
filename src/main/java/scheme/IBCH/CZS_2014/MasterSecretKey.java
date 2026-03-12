package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected Point x; // Z_p

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(x);
        return res.toString();
    }
}
