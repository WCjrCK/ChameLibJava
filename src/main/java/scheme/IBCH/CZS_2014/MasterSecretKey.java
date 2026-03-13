package scheme.IBCH.CZS_2014;

import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.IBCH.Components.MasterSecretKey {
    protected Point x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
