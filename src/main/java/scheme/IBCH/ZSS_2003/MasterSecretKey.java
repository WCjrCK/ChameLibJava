package scheme.IBCH.ZSS_2003;

import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.IBCH.Components.MasterSecretKey {
    protected Point s;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
