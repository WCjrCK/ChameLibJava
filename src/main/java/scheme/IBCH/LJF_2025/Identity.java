package scheme.IBCH.LJF_2025;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class Identity extends scheme.Components.Identity {
    protected AdditivePoint ID, L;

    public Identity() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
