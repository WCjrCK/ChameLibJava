package scheme.IBCH.LSX_2022;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Identity extends scheme.IBCH.Components.Identity {
    protected AdditivePoint ID;

    public Identity() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
