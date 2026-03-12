package scheme.IBCH.implement.ZSS_2003;

import EllipticCurve.Point.Point;
import utils.ElementCounter;

public class MasterSecretKey extends scheme.Components.MasterSecretKey {
    protected Point s; // Z_p

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(s);
        return res.toString();
    }
}
