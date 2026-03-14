package ChameleonHash.IBCH.LJF_2025;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Identity extends ChameleonHash.IBCH.Components.Identity {
    protected Scalar ID, L;

    public Identity() {}

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
