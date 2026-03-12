package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected Point s; // Z_p

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
